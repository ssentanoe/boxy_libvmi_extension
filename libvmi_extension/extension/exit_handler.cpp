#include <boxy/hve/arch/intel_x64/vcpu.h>
#include <boxy/domain/domain.h>
#include <bfdebug.h>

using namespace boxy::intel_x64;

class vmi_vcpu : public boxy::intel_x64::vcpu
{
public:
	vmi_vcpu(vcpuid::type id, gsl::not_null<domain *> domain) : boxy::intel_x64::vcpu{id, domain}
	{
		bfdebug_info(0, "extension loaded");		
	}
};
