#include <lt/lt.h>
#include <lt/mem.h>
#include <lt/asm.h>
#include <lt/io.h>
#include <lt/elf.h>
#include <lt/str.h>
#include <lt/arg.h>

void disasm(void* data, usz len) {
	u8 str[256];
	u8* str_it = str;
	lt_instr_stream_t s = lt_instr_stream_create(data, len, (lt_io_callback_t)lt_str_io_callb, &str_it);
	for (;;) {
		usz offs = s.it - (u8*)data;
		usz len = lt_x64_disasm_instr(&s);
		if (!len) {
			if (s.it == s.end)
				return;
			lt_printf("%hz:\t??\n", offs);
			continue;
		}

		lt_printf("%hz:\t%S\n", offs, LSTR(str, len));
		str_it = str;
	}
}

lt_elf64_sh_t* getsh64(lt_elf64_fh_t* fh, usz i) {
	return (void*)((usz)fh + fh->sh_offset + fh->sh_size * i);
}

lt_elf64_ph_t* getph64(lt_elf64_fh_t* fh, usz i) {
	return (void*)((usz)fh + fh->ph_offset + fh->ph_size * i);
}

void* getoffs(void* fh, usz offs) {
	return (void*)((usz)fh + offs);
}

lstr_t getstr(char* strtab, usz offs) {
	return LSTR(strtab + offs, strlen(strtab + offs));
}

usz vaddr_to_offs(lt_elf64_fh_t* fh, usz vaddr) {
	for (usz i = 0; i < fh->ph_count; ++i) {
		lt_elf64_ph_t* ph = getph64(fh, i);
		if (ph->type != LT_ELF_PH_LOAD)
			continue;
		if (vaddr >= ph->vaddr && vaddr < ph->vaddr + ph->file_size)
			vaddr += ph->offset - ph->vaddr;
	}
	return vaddr;
}

int main(int argc, char** argv) {
	lt_arena_t* arena = lt_amcreate(NULL, LT_GB(1), 0);
	lt_alloc_t* alloc = (lt_alloc_t*)arena;

	char* path = NULL;
	lstr_t disasm_sym_name = NLSTR();

	lt_arg_iterator_t arg_it = lt_arg_iterator_create(argc, argv);
	while (lt_arg_next(&arg_it)) {
		if (lt_arg_flag(&arg_it, 'h', CLSTR("help"))) {
			lt_printf(
				"usage: ldasm [OPTIONS] FILE\n"
				"options:\n"
				"  -h, --help           Display this information.\n"
				"  -s, --symbol=SYMBOL  Disassemble only a specific symbol.\n"
			);
			return 0;
		}
		if (lt_arg_str(&arg_it, 's', CLSTR("symbol"), &disasm_sym_name.str)) {
			disasm_sym_name.len = strlen(disasm_sym_name.str);
			continue;
		}

		path = *arg_it.it;
	}

	if (!path)
		lt_ferrf("no input file provided\n");

	lstr_t file;
	if (!lt_file_read_entire(path, &file, alloc))
		lt_ferrf("%s: failed to read file\n", path);

	if (!lt_elf_verify_magic(file.str))
		lt_ferrf("%s: not a valid ELF file\n", path);

	lt_elf64_fh_t* fh = (void*)file.str;
	if (fh->class != LT_ELFCLASS_64 || fh->encoding != LT_ELFENC_LSB)
		lt_ferrf("%s: unsupported format\n", path);

	lt_elf64_sh_t* strtab_sh = getsh64(fh, fh->sh_strtab_index);
	char* shstrtab = getoffs(fh, strtab_sh->offset);

	lt_elf64_sym_t* sym = NULL;
	usz sym_count = 0;

	char* strtab = NULL;

	for (usz i = 0; i < fh->sh_count; ++i) {
		lt_elf64_sh_t* sh = getsh64(fh, i);
		lstr_t name = getstr(shstrtab, sh->name_stab_offs);
		switch (sh->type) {
		case LT_ELF_SH_STRTAB:
			if (lt_lstr_eq(name, CLSTR(".strtab")))
				strtab = getoffs(fh, sh->offset);
			break;
		case LT_ELF_SH_SYMTAB:
			sym = getoffs(fh, sh->offset);
			sym_count = sh->size / sizeof(lt_elf64_sym_t);
			break;
		}
	}

	if (!sym || !sym_count)
		lt_ferrf("%s: no symbol information found\n", path);

	if (disasm_sym_name.str) {
		for (usz i = 0; i < sym_count; ++i) {
			lt_elf64_sh_t* sh = getsh64(fh, sym[i].section);
			lstr_t name = getstr(strtab, sym[i].name_stab_offs);

			if (lt_lstr_eq(name, disasm_sym_name)) {
				usz offs = vaddr_to_offs(fh, sym[i].value);
				if (fh->obj_type == LT_ELFTYPE_REL)
					offs += sh->offset;
				u8* data = getoffs(fh, offs);

				lt_printf("disassembly of symbol '%S' <0x%hz> (%uq bytes)\n", name, offs, sym[i].size);
				disasm(data, sym[i].size);
				return 0;
			}
		}
		lt_ferrf("%s: symbol '%S' not found\n", path, disasm_sym_name);
	}

	for (usz i = 0; i < sym_count; ++i) {
		lt_elf64_sh_t* sh = getsh64(fh, sym[i].section);
		lstr_t name = getstr(strtab, sym[i].name_stab_offs);

		if ((sym[i].info & LT_ELF_SYM_TYPE_MASK) == LT_ELF_SYM_FUNC && sym[i].size) {
			usz offs = vaddr_to_offs(fh, sym[i].value);
			if (fh->obj_type == LT_ELFTYPE_REL)
				offs += sh->offset;
			u8* data = getoffs(fh, offs);

			lt_printf("disassembly of symbol '%S' <0x%hz> (%uq bytes)\n", name, offs, sym[i].size);
			disasm(data, sym[i].size);
		}
	}
}

