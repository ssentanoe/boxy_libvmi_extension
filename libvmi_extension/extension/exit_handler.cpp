#include <bfvmm/vcpu/vcpu_factory.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <boxy/hve/arch/intel_x64/vcpu.h>
#include <boxy/domain/domain_factory.h>
#include <boxy/domain/domain.h>
#include <bfdebug.h>
#include <bfhypercall.h>

using namespace boxy::intel_x64;

typedef enum hstatus {
	HSTATUS_SUCCESS = 0ull,
	HSTATUS_FAILURE
} hstatus_t;

#define HCALL_INVALID		0xbf05000000000000
#define HCALL_ACK		0xbf05000000000001
#define HCALL_GET_REGISTERS	0xbf05000000000002
#define HCALL_SET_REGISTERS	0xbf05000000000003
#define HCALL_TRANSLATE_V2P	0xbf05000000000004
#define HCALL_MAP_PA		0xbf05000000000005

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
				case HCALL_TRANSLATE_V2P:
					bfdebug_info(0, "HCALL_TRANSLATE_V2P in");
					served = true;
					//hcall_translate_v2p(vcpu);
					break;
				case HCALL_GET_REGISTERS:
					bfdebug_info(0, "HCALL_GET_REGISTERS in");
					served = true;
					//hcall_get_register_data(vcpu);
					break;
				case HCALL_MAP_PA:
					bfdebug_info(0, "HCALL_MAP_PA in");
					served = true;
					//hcall_memmap_ept(vcpu);
					break;
				default:
					//bfalert_nhex(0, "vmcall", vcpu->rax());
					break;
			};
			vcpu->set_rax(1);
		},
		[&] {
			bfdebug_info(0, "guard guard_exceptions in 2");
			vcpu->set_rax(0);
		});

		return served;
	}

	vmi_vcpu(vcpuid::type id, gsl::not_null<domain *> domain) : boxy::intel_x64::vcpu{id, domain}
	{
		bfdebug_info(0, "extension loaded");
		add_handler(intel_x64::vmcs::exit_reason::basic_exit_reason::cpuid, {&vmi_vcpu::cpuid_handler, this});
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
