#include <bfvmm/vcpu/vcpu_factory.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <boxy/hve/arch/intel_x64/vcpu.h>
#include <boxy/domain/domain_factory.h>
#include <boxy/domain/domain.h>
#include <bfdebug.h>
#include <bfhypercall.h>
#include <bfcallonce.h>
#include "json.hpp"

using namespace boxy::intel_x64;
using nlohmann::json;

typedef enum hstatus {
	HSTATUS_SUCCESS = 0ull,
	HSTATUS_FAILURE
} hstatus_t;

bfn::once_flag flag{};
bfvmm::intel_x64::ept::mmap g_guest_map;
uint64_t dom0cr3[32];

#define HCALL_INVALID		0xbf05000000000000
#define HCALL_ACK		0xbf05000000000001
#define HCALL_GET_REGISTERS	0xbf05000000000002
#define HCALL_SET_REGISTERS	0xbf05000000000003
#define HCALL_TRANSLATE_V2P	0xbf05000000000004
#define HCALL_MAP_PA		0xbf05000000000005
#define HCALL_PROBE_ADDR	0xbf05000000000006

class vmi_vcpu : public boxy::intel_x64::vcpu
{
public:

	using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
	using handler_delegate_t = delegate<handler_t>;

	bool cpuid_handler(vcpu_t *vcpu)
	{
		if(rax() == 0x40001337)
		{
			bfdebug_info(0, "cpuid_magic called");
			set_rax(42);
			set_rbx(42);
			set_rcx(42);
			set_rdx(42);

			return vcpu->advance();
		}
		return false;
	}

	bool vmcall_handler(vcpu *vcpu)
	{
		if (bfopcode(vcpu->rax()) != __enum_vmi_op)
			return false;

		bool served = false;
		guard_exceptions([&] {
			switch (vcpu->rax())
			{
				case HCALL_ACK:
					bfdebug_info(0, "HCALL_ACK");
					create_ept();
					served = true;
					break;
				case HCALL_TRANSLATE_V2P:
					bfdebug_info(0, "HCALL_TRANSLATE_V2P in");
					served = true;
					hcall_translate_v2p(vcpu);
					break;
				case HCALL_GET_REGISTERS:
					bfdebug_info(0, "HCALL_GET_REGISTERS in");
					served = true;
					hcall_get_register_data(vcpu);
					break;
				case HCALL_MAP_PA:
					bfdebug_info(0, "HCALL_MAP_PA in");
					served = true;
					hcall_memmap_ept(vcpu);
					break;
				case HCALL_PROBE_ADDR:
					served = true;
					bfdebug_info(0, "HCALL_PROBE_ADDR in");
					hcall_probe_addr(vcpu);
					break;
				default:
					//bfalert_nhex(0, "vmcall", vcpu->rax());
					vcpu->set_rax(HSTATUS_SUCCESS);
					break;
			};
			//vcpu->set_rax(HSTATUS_SUCCESS);
		},
		[&] {
			bfdebug_info(0, "guard guard_exceptions in 2");
			vcpu->set_rax(HSTATUS_FAILURE);
		});

		return served;
	}

	void hcall_probe_addr(vcpu *vcpu)
	{
		if(vcpu->is_dom0())
		{
			bfalert_nhex(0, "probe id", vcpu->id());
			bfalert_nhex(0, "probe cr3", vcpu->cr3());
			dom0cr3[0] = ::intel_x64::vmcs::guest_cr3::get();
			dom0cr3[1] = ::intel_x64::vmcs::guest_cr3::get();
			dom0cr3[2] = ::intel_x64::vmcs::guest_cr3::get();
			dom0cr3[3] = ::intel_x64::vmcs::guest_cr3::get();

			vcpu->set_rax(HSTATUS_SUCCESS);
		}
	}

	void hcall_translate_v2p(vcpu *vcpu)
	{
		try
		{
			auto addr = vcpu->rdi();
			auto pa = vcpu->gva_to_gpa(addr);
			vcpu->set_rdi(pa.first);
			bfdebug_info(0, "v2p vmcall handled");
			vcpu->set_rax(HSTATUS_SUCCESS);
			//bfalert_nhex(0, "v2p V", addr);
			//bfalert_nhex(0, "v2p P", pa.first);
		}
		catchall
		({
			vcpu->set_rax(HSTATUS_FAILURE);
		})
	}

	void hcall_memmap_ept(vcpu *vcpu)
	{
		try
		{
			uint64_t addr = vcpu->rdi();
			uint64_t gpa2 = vcpu->rsi();
			uint64_t domainid = vcpu->rdx();

			auto hpa = vcpu->gva_to_gpa(addr);
			auto gpa1 = hpa.first;

			bool a = false;

			if(vcpu->is_dom0())
			{
				if(domainid == 0) // tries to monitor dom0
				{
					a = g_guest_map.is_2m(gpa1);
				}
				else // tries to monitor domU
				{
					// not yet supported
					vcpu->set_rax(HSTATUS_FAILURE);
					return;
				}
			}
			else // domU
			{
				if(domainid == 0) // tries to monitor dom0
				{
					a = get_domain(vcpu->domid())->ept().is_2m(gpa1);
				}
				else // tries to monitor domU
				{
					// not yet supported
					vcpu->set_rax(HSTATUS_FAILURE);
					return;
				}
			}

			if(a)
			{
				auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);

				if(vcpu->domid() == 0)
					bfvmm::intel_x64::ept::identity_map_convert_2m_to_4k(g_guest_map, gpa1_2m);
				else
					bfvmm::intel_x64::ept::identity_map_convert_2m_to_4k(get_domain(vcpu->domid())->ept(), gpa1_2m);
			}
			auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
			auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);
			vcpu->set_rsi(gpa2_4k);

			auto pte = vcpu->domid() == 0 ? g_guest_map.entry(gpa1_4k) : get_domain(vcpu->domid())->ept().entry(gpa1_4k);
			::intel_x64::ept::pt::entry::phys_addr::set(pte.first, gpa2_4k);

			// flush EPT tlb, guest TLB doesn't need to be flushed
			// as that translation hasn't changed
			::intel_x64::vmx::invept_global();

			bfdebug_info(0, "memmap ept called");
			vcpu->set_rax(HSTATUS_SUCCESS);
		}
		catchall
		({
			vcpu->set_rax(HSTATUS_FAILURE);
		})
	}

	void hcall_get_register_data(vcpu *vcpu)
	{
		try
		{
			bfdebug_info(0, "hcall_get_register_data start");
			json j;
			j["RAX"] = vcpu->rax();
			j["RBX"] = vcpu->rbx();
			j["RCX"] = vcpu->rcx();
			j["RDX"] = vcpu->rdx();
			j["R08"] = vcpu->r08();
			j["R09"] = vcpu->r09();
			j["R10"] = vcpu->r10();
			j["R11"] = vcpu->r11();
			j["R12"] = vcpu->r12();
			j["R13"] = vcpu->r13();
			j["R14"] = vcpu->r14();
			j["R15"] = vcpu->r15();
			j["RBP"] = vcpu->rbp();
			j["RSI"] = vcpu->rsi();
			j["RDI"] = vcpu->rdi();
			j["RIP"] = vcpu->rip();
			j["RSP"] = vcpu->rsp();
			j["CR0"] = ::intel_x64::vmcs::guest_cr0::get();
			if(vcpu->is_domU())
			{
				j["CR3"] = dom0cr3[vcpu->parent_vcpu()->id()];

				bfalert_nhex(0, "vcpu parent id", vcpu->parent_vcpu()->id());
				bfalert_nhex(0, "vcpu parent cr3", dom0cr3[vcpu->parent_vcpu()->id()]);
			}
			else
			{
				j["CR3"] = vcpu->cr3();
			}

			j["CR4"] = ::intel_x64::vmcs::guest_cr4::get();
			j["MSR_EFER"] = ::intel_x64::vmcs::guest_ia32_efer::get();

			uintptr_t addr = vcpu->rdi();
			uint64_t size = vcpu->rsi();

			auto omap = vcpu->map_gva_4k<char>(addr, size);

			auto &&dmp = j.dump();

			__builtin_memcpy(omap.get(), dmp.data(), size);

			bfdebug_info(0, "get-registers vmcall handled");

			vcpu->set_rax(HSTATUS_SUCCESS);
		}
		catchall
		({
			vcpu->set_rax(HSTATUS_FAILURE);
		})
	}

	void create_ept()
	{
		bfvmm::intel_x64::ept::identity_map(g_guest_map, MAX_PHYS_ADDR);
		::intel_x64::vmx::invept_global();
	}

	bool cr3_handler(vcpu_t *vcpu)
	{
		// bfdebug_info(0, "called");
		return false;
	}
	
	bool test_handler(vcpu_t *vcpu)
	{
		bfdebug_info(0, "called");
		return false;
	}
	/*bool interrupt_handler(vcpu_t *vcpu, bfvmm::intel_x64::external_interrupt_handler::info_t &info)
	{
		queue_external_interrupt(info.vector);
		if(info.vector == 0xCC)
		bfalert_nhex(0, "intterupt", info.vector);
		//bfdebug_info(0, "called");
		return true;
	}*/

	~vmi_vcpu() = default;
	vmi_vcpu(vcpuid::type id, gsl::not_null<domain *> domain) : boxy::intel_x64::vcpu{id, domain}
	{
		bfdebug_info(0, "extension loaded");

		if(domain->id() == 0)
		{
			bfn::call_once(flag, [&] {
				create_ept();
			});
			set_eptp(g_guest_map);
			
			//store the cr3 of host OS
			dom0cr3[id] = ::intel_x64::vmcs::guest_cr3::get();
			add_wrcr3_handler({&vmi_vcpu::cr3_handler, this});
			//add_external_interrupt_handler({&vmi_vcpu::interrupt_handler, this});
		}
	
		add_handler(intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid, {&vmi_vcpu::cpuid_handler, this});
		add_handler(intel_x64::vmcs::exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt, {&vmi_vcpu::test_handler, this});
		add_vmcall_handler({&vmi_vcpu::vmcall_handler, this});
	}
};

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
	static domain dom0{0};
	if (vcpuid::is_host_vm_vcpu(vcpuid))
	{
		return
		std::make_unique<vmi_vcpu>(
			vcpuid, dynamic_cast<domain *>(&dom0)
		);
	}
	else
	{
		return
		std::make_unique<vmi_vcpu>(
			vcpuid, dynamic_cast<domain *>(obj)
		);
	}
}

}

namespace boxy
{

std::unique_ptr<domain>
domain_factory::make(domain::domainid_type domainid, bfobject *obj)
{
	bfignored(obj);
	return std::make_unique<boxy::intel_x64::domain>(domainid);
}

}
