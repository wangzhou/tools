#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#define PAGE_SIZE		sysconf(_SC_PAGESIZE)
#define PAGE_MASK		~(PAGE_SIZE - 1)

#define SMMU_IDR1		0x04
#define SMMU_CR0		0x20
#define SMMU_GBPA		0x44
#define SMMU_STRTAB_BASE	0x80
#define SMMU_STRTAB_BASE_CFG	0x88

typedef unsigned int		u32;
typedef unsigned long long	u64;


void report_error(int line)
{
	fprintf(stderr, "Error(%d) at line %d: [%s]\n", errno, line, strerror(errno));
	exit(1);
}

#define BUG_ON(error) 	do { if (error) report_error(__LINE__); } while (0)


u32 smmu_readl(void *vbase, int offset)
{
	return *(u32 *)((u64)vbase + offset);
}

u64 smmu_readq(void *vbase, int offset)
{
	return *(u64 *)((u64)vbase + offset);
}

int main(int argc, char **argv) {
	int fd;
	u64 base, sid, iova, ssid;
	void *vbase;
	u32  reg, cfg;
	u64 val, ste[4], cde[4];
	int i, idx;
	size_t mapsz;
	size_t offset;

	if ((argc < 4) || (0 == strcmp(argv[1], "-h")) || (0 == strcmp(argv[1], "--help"))) {
		fprintf(stderr, "\nUsage: smmu_base sid iova [ssid]\n");
		exit(1);
	}

	fd = open("/dev/mem", O_RDWR | O_SYNC);
 	BUG_ON(fd == -1);

	base = strtoul(argv[1], 0, 0);
	sid  = strtoul(argv[2], 0, 0);
	iova = strtoul(argv[3], 0, 0);

	if (argc == 5)
		ssid = strtoul(argv[4], 0, 0);
	else
		ssid = 0;

	vbase = mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, base);
	BUG_ON(vbase == MAP_FAILED);
	reg = smmu_readl(vbase, SMMU_IDR1);
	if (sid >= (1ULL << (reg & 0x3f))) {
		fprintf(stderr, "sid is too large: max=0x%llx\n", (1ULL << (reg & 0x3f)) - 1);
		goto finished;
	}

	if (ssid >= (1ULL << ((reg >> 6) & 0x1f))) {
		fprintf(stderr, "ssid is too large: max=0x%llx\n", (1ULL << ((reg >> 6) & 0x1f)) - 1);
		goto finished;
	}

	reg = smmu_readl(vbase, SMMU_CR0);
	if (!(reg & 0x1)) {
		reg = smmu_readl(vbase, SMMU_GBPA);
		BUG_ON(munmap(vbase, PAGE_SIZE) == -1);
		fprintf(stderr, "smmu is disabled: SMMU_GBPA=0x%08x\n", reg);
		goto finished;
	}
	fprintf(stderr, "SMMU_CR0: 0x%x\n", reg);

	val = smmu_readq(vbase, SMMU_STRTAB_BASE);
	cfg = smmu_readl(vbase, SMMU_STRTAB_BASE_CFG);
	BUG_ON(munmap(vbase, PAGE_SIZE) == -1);
	fprintf(stderr, "SMMU_STRTAB_BASE: 0x%llx, SMMU_STRTAB_BASE_CFG: 0x%x\n", val, cfg);

	if (sid >= (1ULL << (cfg & 0x3f))) {
		fprintf(stderr, "sid is too large: max=0x%llx\n", (1ULL << (cfg & 0x3f)) - 1);
		goto finished;
	}

	base = (val & ((1ULL << 52) - 1)) & ~0x3f;

	if (0x1 == ((cfg >> 16) & 0x3)) {
		u32 split;

		fprintf(stderr, "Level 1 STE table base: 0x%llx\n", base);

		split = (cfg >> 6) & 0x1f;
		mapsz = 1ULL << (split + 6);

		base += ((sid >> split) * 8) & ~0xfff;
		vbase = mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, base);
		BUG_ON(vbase == MAP_FAILED);
		val = smmu_readq(vbase, ((sid >> split) * 8) & 0xfff);
		BUG_ON(munmap(vbase, PAGE_SIZE) == -1);
		base = (val & ((1ULL << 52) - 1)) & ~0x3f;
		fprintf(stderr, "Level 2 STE table base: 0x%llx\n", base);
	} else {
		fprintf(stderr, "Linear STE table base: 0x%llx\n", base);
		base += (sid * 64) & ~0xfff;
		mapsz = PAGE_SIZE;
	}

	vbase = mmap(0, mapsz, PROT_READ, MAP_SHARED, fd, base);
	BUG_ON(vbase == MAP_FAILED);
	offset = (sid * 64) & (mapsz - 1);
	ste[0] = smmu_readq(vbase, offset + 0x0);
	ste[1] = smmu_readq(vbase, offset + 0x8);
	ste[2] = smmu_readq(vbase, offset + 0x10);
	ste[3] = smmu_readq(vbase, offset + 0x18);
	BUG_ON(munmap(vbase, PAGE_SIZE) == -1);

	/* V */
	if (!(ste[0] & 0x1)) {
		fprintf(stderr, "ste is invalid: ste[0]=0x%llx\n", ste[0]);
		goto finished;
	}

	/* Config */
	switch ((ste[0] >> 1) & 0x7) {
	case 0x4:
		fprintf(stderr, "both s1 and s2 are bypass: ste[]=0x%llx, 0x%llx, 0x%llx, 0x%llx\n", ste[0], ste[1], ste[2], ste[3]);
		goto finished;
	case 0x5:
		fprintf(stderr, "s1 translate + s2 bypass: ste[]=0x%llx, 0x%llx, 0x%llx, 0x%llx\n", ste[0], ste[1], ste[2], ste[3]);
		base = (ste[0] & ((1ULL << 52) - 1)) & ~0x3f;
		break;
	case 0x6:
		fprintf(stderr, "s1 bypass + s2 translate: ste[]=0x%llx, 0x%llx, 0x%llx, 0x%llx\n", ste[0], ste[1], ste[2], ste[3]);
		base = (ste[3] & ((1ULL << 52) - 1)) & ~0x3f;
		goto pgtbl;
	default:
		fprintf(stderr, "unknown configuration: ste[0]=0x%llx\n", ste[0]);
		goto finished;
	}

	/* S1CDMax */
	if (!(ste[0] >> 59)) {
		fprintf(stderr, "One CD base: 0x%llx\n", base);
		if (ssid != 0) {
			fprintf(stderr, "S1CDMax=0, substream is disabled, force ssid to zero\n");
			ssid = 0;
		}
		mapsz = PAGE_SIZE;
	} else {
		int lvl2;

		if (ssid >= (1ULL << (ste[0] >> 59))) {
			fprintf(stderr, "sid is too large: max=0x%llx\n", (1ULL << (ste[0] >> 59)) - 1);
			goto finished;
		}

		/* S1 Fmt */
		switch ((ste[0] >> 4) & 0x3) {
		case 1:
			fprintf(stderr, "Level 1 CD table base: 0x%llx\n", base);
			lvl2 = 1;
			mapsz = 0x1000;
			break;
		case 2:
			fprintf(stderr, "Level 1 CD table base: 0x%llx\n", base);
			lvl2 = 1;
			mapsz = 0x10000;
			break;
		case 0:
		default:
			fprintf(stderr, "Linear CD table base: 0x%llx\n", base);
			lvl2 = 0;
			base += (ssid * 64) & ~0xfff;
			mapsz = PAGE_SIZE;
			break;
		}

		if (lvl2) {
			offset = (ssid / (mapsz / 64)) * 8;
			base += offset & ~0xfff;
			vbase = mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, base);
			BUG_ON(vbase == MAP_FAILED);
			val = smmu_readq(vbase, offset & 0xfff);
			BUG_ON(munmap(vbase, PAGE_SIZE) == -1);
			base = (val & ((1ULL << 52) - 1)) & ~0xfff;
			fprintf(stderr, "Level 2 CD table base: 0x%llx\n", base);
		}
	}

	offset = (ssid * 64) & (mapsz - 1);
	vbase = mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, base);
	BUG_ON(vbase == MAP_FAILED);
	cde[0] = smmu_readq(vbase, offset + 0x0);
	cde[1] = smmu_readq(vbase, offset + 0x8);
	cde[2] = smmu_readq(vbase, offset + 0x10);
	cde[3] = smmu_readq(vbase, offset + 0x18);
	BUG_ON(munmap(vbase, PAGE_SIZE) == -1);
	fprintf(stderr, "cde[]=0x%llx, 0x%llx, 0x%llx, 0x%llx\n", cde[0], cde[1], cde[2], cde[3]);

	if (!(cde[0] & (1ULL << 31))) {
		fprintf(stderr, "cde is invalid\n");
		goto finished;
	} else if ((cde[0] & (1ULL << 30)) && (cde[0] & (1ULL << 14))) {
		fprintf(stderr, "both TTB0 and TTB1 are disabled\n");
		goto finished;
	} else if (cde[0] & (1ULL << 30)) {
		base = (cde[1] & ((1ULL << 52) - 1)) & ~0xf;
	} else {
		base = (cde[2] & ((1ULL << 52) - 1)) & ~0xf;
	}

pgtbl:
{
	int va_bits, max_lvl, nr_pte_bits_per_page;

	if (PAGE_SIZE == 0x1000) {	//4K
		va_bits = 39;
		max_lvl = 4;
		nr_pte_bits_per_page = 9;
	} else {			//64K
		va_bits = 42;
		max_lvl = 3;
		nr_pte_bits_per_page = 13;
	}

	for (i = 0, idx = va_bits; i < max_lvl; i++, idx -= nr_pte_bits_per_page) {
		vbase = mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, base);
		BUG_ON(vbase == MAP_FAILED);
		val = smmu_readq(vbase, (((iova >> idx) & 0x1ff) * 8));
		BUG_ON(munmap(vbase, PAGE_SIZE) == -1);

		switch (val & 0x3) {
		case 1:
			base = (val & ((1ULL << 52) - 1)) & ~((1ULL << idx) - 1);
			fprintf(stderr, "LVL%d PTE: 0x%llx, block\n", i, val);
			goto finished;
		case 3:
			base = (val & ((1ULL << 52) - 1)) & ~((1ULL << 12) - 1);
			break;
		default:
			fprintf(stderr, "LVL%d PTE: 0x%llx, invalid\n", i, val);
			goto finished;
		}

		fprintf(stderr, "LVL%d PTE: 0x%llx\n", i, val);
	}
}
finished:
	close(fd);
	return 0;
}

