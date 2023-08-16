// SPDX-License-Identifier: GPL-2.0-only
/*
 * set_id_regs - Test for setting ID register from usersapce.
 *
 * Copyright (c) 2023 Google LLC.
 *
 *
 * Test that KVM supports setting ID registers from userspace and handles the
 * feature set correctly.
 */

#include <stdint.h>
#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include <linux/bitfield.h>

enum ftr_type {
	FTR_EXACT,			/* Use a predefined safe value */
	FTR_LOWER_SAFE,			/* Smaller value is safe */
	FTR_HIGHER_SAFE,		/* Bigger value is safe */
	FTR_HIGHER_OR_ZERO_SAFE,	/* Bigger value is safe, but 0 is biggest */
	FTR_END,			/* Mark the last ftr bits */
};

#define FTR_SIGNED	true	/* Value should be treated as signed */
#define FTR_UNSIGNED	false	/* Value should be treated as unsigned */

struct reg_ftr_bits {
	char *name;
	bool sign;
	enum ftr_type type;
	uint8_t shift;
	uint64_t mask;
	int64_t safe_val;
};

struct test_feature_reg {
	uint32_t reg;
	const struct reg_ftr_bits *ftr_bits;
};

#define __REG_FTR_BITS(NAME, SIGNED, TYPE, SHIFT, MASK, SAFE_VAL)	\
	{								\
		.name = #NAME,						\
		.sign = SIGNED,						\
		.type = TYPE,						\
		.shift = SHIFT,						\
		.mask = MASK,						\
		.safe_val = SAFE_VAL,					\
	}

#define REG_FTR_BITS(type, reg, field, safe_val) \
	__REG_FTR_BITS(reg##_##field, FTR_UNSIGNED, type, reg##_##field##_SHIFT, \
		       reg##_##field##_MASK, safe_val)

#define S_REG_FTR_BITS(type, reg, field, safe_val) \
	__REG_FTR_BITS(reg##_##field, FTR_SIGNED, type, reg##_##field##_SHIFT, \
		       reg##_##field##_MASK, safe_val)

#define REG_FTR_END					\
	{						\
		.type = FTR_END,			\
	}

static const struct reg_ftr_bits ftr_id_aa64dfr0_el1[] = {
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, DoubleLock, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, PMSVer, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, CTX_CMPs, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, WRPs, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, BRPs, 0),
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, PMUVer, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64DFR0_EL1, DebugVer, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_dfr0_el1[] = {
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, PerfMon, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, MProfDbg, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, MMapTrc, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, CopTrc, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, MMapDbg, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, CopSDbg, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_DFR0_EL1, CopDbg, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_aa64pfr0_el1[] = {
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, CSV3, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, CSV2, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, DIT, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, AMU, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, MPAM, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, SEL2, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, SVE, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, RAS, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, GIC, 0),
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, AdvSIMD, 0),
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, FP, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, EL3, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, EL2, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, EL1, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64PFR0_EL1, EL0, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_aa64mmfr0_el1[] = {
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, ECV, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, FGT, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, EXS, 0),
	REG_FTR_BITS(FTR_EXACT, ID_AA64MMFR0_EL1, TGRAN4_2, 1),
	REG_FTR_BITS(FTR_EXACT, ID_AA64MMFR0_EL1, TGRAN64_2, 1),
	REG_FTR_BITS(FTR_EXACT, ID_AA64MMFR0_EL1, TGRAN16_2, 1),
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, TGRAN4, 0),
	S_REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, TGRAN64, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, TGRAN16, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, BIGENDEL0, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, SNSMEM, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, BIGEND, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, ASIDBITS, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR0_EL1, PARANGE, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_aa64mmfr1_el1[] = {
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, TIDCP1, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, AFP, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, HCX, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, ETS, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, TWED, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, XNX, 0),
	REG_FTR_BITS(FTR_HIGHER_SAFE, ID_AA64MMFR1_EL1, SpecSEI, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, PAN, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, LO, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, HPDS, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, VH, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, VMIDBits, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR1_EL1, HAFDBS, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_aa64mmfr2_el1[] = {
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, E0PD, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, EVT, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, BBM, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, TTL, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, FWB, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, IDS, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, AT, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, ST, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, NV, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, CCIDX, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, VARange, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, IESB, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, LSM, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, UAO, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR2_EL1, CnP, 0),
	REG_FTR_END,
};

static const struct reg_ftr_bits ftr_id_aa64mmfr3_el1[] = {
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR3_EL1, S1PIE, 0),
	REG_FTR_BITS(FTR_LOWER_SAFE, ID_AA64MMFR3_EL1, TCRX, 0),
	REG_FTR_END,
};

#define TEST_REG(id, table)			\
	{					\
		.reg = id,			\
		.ftr_bits = &((table)[0]),	\
	}

static struct test_feature_reg test_regs[] = {
	TEST_REG(SYS_ID_AA64DFR0_EL1, ftr_id_aa64dfr0_el1),
	TEST_REG(SYS_ID_DFR0_EL1, ftr_id_dfr0_el1),
	TEST_REG(SYS_ID_AA64PFR0_EL1, ftr_id_aa64pfr0_el1),
	TEST_REG(SYS_ID_AA64MMFR0_EL1, ftr_id_aa64mmfr0_el1),
	TEST_REG(SYS_ID_AA64MMFR1_EL1, ftr_id_aa64mmfr1_el1),
	TEST_REG(SYS_ID_AA64MMFR2_EL1, ftr_id_aa64mmfr2_el1),
	TEST_REG(SYS_ID_AA64MMFR3_EL1, ftr_id_aa64mmfr3_el1),
};

#define GUEST_REG_SYNC(id) GUEST_SYNC_ARGS(0, id, read_sysreg_s(id), 0, 0);

static void guest_code(void)
{
	GUEST_REG_SYNC(SYS_ID_AA64DFR0_EL1);
	GUEST_REG_SYNC(SYS_ID_DFR0_EL1);
	GUEST_REG_SYNC(SYS_ID_AA64PFR0_EL1);
	GUEST_REG_SYNC(SYS_ID_AA64MMFR0_EL1);
	GUEST_REG_SYNC(SYS_ID_AA64MMFR1_EL1);
	GUEST_REG_SYNC(SYS_ID_AA64MMFR2_EL1);
	GUEST_REG_SYNC(SYS_ID_AA64MMFR3_EL1);

	GUEST_DONE();
}

/* Return a safe value to a given ftr_bits an ftr value */
uint64_t get_safe_value(const struct reg_ftr_bits *ftr_bits, uint64_t ftr)
{
	uint64_t ftr_max = GENMASK_ULL(ARM64_FEATURE_FIELD_BITS - 1, 0);

	if (ftr_bits->type == FTR_UNSIGNED) {
		switch (ftr_bits->type) {
		case FTR_EXACT:
			ftr = ftr_bits->safe_val;
			break;
		case FTR_LOWER_SAFE:
			if (ftr > 0)
				ftr--;
			break;
		case FTR_HIGHER_SAFE:
			if (ftr < ftr_max)
				ftr++;
			break;
		case FTR_HIGHER_OR_ZERO_SAFE:
			if (ftr == ftr_max)
				ftr = 0;
			else if (ftr != 0)
				ftr++;
			break;
		default:
			break;
		}
	} else if (ftr != ftr_max) {
		switch (ftr_bits->type) {
		case FTR_EXACT:
			ftr = ftr_bits->safe_val;
			break;
		case FTR_LOWER_SAFE:
			if (ftr > 0)
				ftr--;
			break;
		case FTR_HIGHER_SAFE:
			if (ftr < ftr_max - 1)
				ftr++;
			break;
		case FTR_HIGHER_OR_ZERO_SAFE:
			if (ftr != 0 && ftr != ftr_max - 1)
				ftr++;
			break;
		default:
			break;
		}
	}

	return ftr;
}

/* Return an invalid value to a given ftr_bits an ftr value */
uint64_t get_invalid_value(const struct reg_ftr_bits *ftr_bits, uint64_t ftr)
{
	uint64_t ftr_max = GENMASK_ULL(ARM64_FEATURE_FIELD_BITS - 1, 0);

	if (ftr_bits->type == FTR_UNSIGNED) {
		switch (ftr_bits->type) {
		case FTR_EXACT:
			ftr = max((uint64_t)ftr_bits->safe_val + 1, ftr + 1);
			break;
		case FTR_LOWER_SAFE:
			ftr++;
			break;
		case FTR_HIGHER_SAFE:
			ftr--;
			break;
		case FTR_HIGHER_OR_ZERO_SAFE:
			if (ftr == 0)
				ftr = ftr_max;
			else
				ftr--;
			break;
		default:
			break;
		}
	} else if (ftr != ftr_max) {
		switch (ftr_bits->type) {
		case FTR_EXACT:
			ftr = max((uint64_t)ftr_bits->safe_val + 1, ftr + 1);
			break;
		case FTR_LOWER_SAFE:
			ftr++;
			break;
		case FTR_HIGHER_SAFE:
			ftr--;
			break;
		case FTR_HIGHER_OR_ZERO_SAFE:
			if (ftr == 0)
				ftr = ftr_max - 1;
			else
				ftr--;
			break;
		default:
			break;
		}
	} else {
		ftr = 0;
	}

	return ftr;
}

static void test_reg_set_success(struct kvm_vcpu *vcpu, uint64_t reg,
				 const struct reg_ftr_bits *ftr_bits)
{
	uint8_t shift = ftr_bits->shift;
	uint64_t mask = ftr_bits->mask;
	uint64_t val, new_val, ftr;

	vcpu_get_reg(vcpu, reg, &val);
	ftr = (val & mask) >> shift;

	ftr = get_safe_value(ftr_bits, ftr);

	ftr <<= shift;
	val &= ~mask;
	val |= ftr;

	vcpu_set_reg(vcpu, reg, val);
	vcpu_get_reg(vcpu, reg, &new_val);
	ASSERT_EQ(new_val, val);
}

static void test_reg_set_fail(struct kvm_vcpu *vcpu, uint64_t reg,
			      const struct reg_ftr_bits *ftr_bits)
{
	uint8_t shift = ftr_bits->shift;
	uint64_t mask = ftr_bits->mask;
	uint64_t val, old_val, ftr;
	int r;

	vcpu_get_reg(vcpu, reg, &val);
	ftr = (val & mask) >> shift;

	ftr = get_invalid_value(ftr_bits, ftr);

	old_val = val;
	ftr <<= shift;
	val &= ~mask;
	val |= ftr;

	r = __vcpu_set_reg(vcpu, reg, val);
	TEST_ASSERT(r < 0 && errno == EINVAL,
		    "Unexpected KVM_SET_ONE_REG error: r=%d, errno=%d", r, errno);

	vcpu_get_reg(vcpu, reg, &val);
	ASSERT_EQ(val, old_val);
}

static void test_user_set_reg(struct kvm_vcpu *vcpu, bool aarch64_only)
{
	uint64_t masks[ARM64_FEATURE_ID_SPACE_SIZE];
	struct reg_mask_range range;
	int ret;

	range.addr = (uint64_t)masks;

	/* KVM should return error when reserved field is not zero */
	range.reserved[0] = 1;
	ret = __vm_ioctl(vcpu->vm, KVM_ARM_GET_REG_WRITABLE_MASKS, &range);
	TEST_ASSERT(ret, "KVM doesn't check invalid parameters.");

	/* Get writable masks for feature ID registers */
	memset(range.reserved, 0, sizeof(range.reserved));
	vm_ioctl(vcpu->vm, KVM_ARM_GET_REG_WRITABLE_MASKS, &range);

	for (int i = 0; i < ARRAY_SIZE(test_regs); i++) {
		const struct reg_ftr_bits *ftr_bits = test_regs[i].ftr_bits;
		uint32_t reg_id = test_regs[i].reg;
		uint64_t reg = KVM_ARM64_SYS_REG(reg_id);
		int idx;

		/* Get the index to masks array for the idreg */
		idx = ARM64_FEATURE_ID_SPACE_IDX(sys_reg_Op0(reg_id), sys_reg_Op1(reg_id),
				sys_reg_CRn(reg_id), sys_reg_CRm(reg_id), sys_reg_Op2(reg_id));

		for (int j = 0;  ftr_bits[j].type != FTR_END; j++) {
			/* Skip aarch32 reg on aarch64 only system, since they are RAZ/WI. */
			if (aarch64_only && sys_reg_CRm(reg_id) < 4) {
				ksft_test_result_skip("%s on AARCH64 only system\n",
						      ftr_bits[j].name);
				continue;
			}

			/* Make sure the feature field is writable */
			ASSERT_EQ(masks[idx] & ftr_bits[j].mask, ftr_bits[j].mask);

			test_reg_set_fail(vcpu, reg, &ftr_bits[j]);
			test_reg_set_success(vcpu, reg, &ftr_bits[j]);

			ksft_test_result_pass("%s\n", ftr_bits[j].name);
		}
	}
}

static void test_guest_reg_read(struct kvm_vcpu *vcpu)
{
	struct ucall uc;
	bool done = false;

	while (!done) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
			break;
		case UCALL_SYNC:
			uint64_t val;

			/* Make sure the written values are seen by guest */
			vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(uc.args[2]), &val);
			ASSERT_EQ(val, uc.args[3]);
			break;
		case UCALL_DONE:
			done = true;
			break;
		default:
			TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
		}
	}
}

int main(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	bool aarch64_only;
	uint64_t val, el0;
	int ftr_cnt;

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);

	/* Check for AARCH64 only system */
	vcpu_get_reg(vcpu, KVM_ARM64_SYS_REG(SYS_ID_AA64PFR0_EL1), &val);
	el0 = FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1_EL0), val);
	aarch64_only = (el0 == ID_AA64PFR0_EL1_ELx_64BIT_ONLY);

	ksft_print_header();

	ftr_cnt = ARRAY_SIZE(ftr_id_aa64dfr0_el1) + ARRAY_SIZE(ftr_id_dfr0_el1)
		  + ARRAY_SIZE(ftr_id_aa64pfr0_el1) + ARRAY_SIZE(ftr_id_aa64mmfr0_el1)
		  + ARRAY_SIZE(ftr_id_aa64mmfr1_el1) + ARRAY_SIZE(ftr_id_aa64mmfr2_el1)
		  + ARRAY_SIZE(ftr_id_aa64mmfr3_el1) - ARRAY_SIZE(test_regs);

	ksft_set_plan(ftr_cnt);

	test_user_set_reg(vcpu, aarch64_only);
	test_guest_reg_read(vcpu);

	kvm_vm_free(vm);

	ksft_finished();
}
