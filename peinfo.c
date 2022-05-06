/****************************************************************************
 Windows executable header info extractor
 Copyright (C) 2017 Krzysztof Nikiel

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <getopt.h>

// dword[3c] = PE header offset
static const int peheadofs = 0x3c;
static const int pemagic = 'P' | ('E' << 8);

typedef char int8;
typedef short int16;
typedef int int32;

#pragma pack(push,1)
/* Portable EXE header */
typedef struct
{
  uint32_t Magic;
  uint16_t CPUType;
  uint16_t Sections;
  uint32_t TimeDataStamp;
  uint32_t SymbolTblOfs;
  uint32_t Symbols;
  uint16_t NTHdrSize;
  uint16_t Flags;
  uint16_t Magic2;
  uint8_t LMajor;
  uint8_t LMinor;
  uint32_t CodeSize;
  uint32_t DataSize;
  uint32_t BssSize;
  uint32_t EntryPointRVA;
  uint32_t BaseOfCode;
}
head1_t;

typedef struct
{
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlign;
  uint32_t FileAlign;
  uint16_t OSMajor;
  uint16_t OSMinor;
  uint16_t ImageMajor;
  uint16_t ImageMinor;
  uint16_t SubSystMajor;
  uint16_t SubSystMinor;
  uint32_t Win32Version;
  uint32_t ImageSize;
  uint32_t HeaderSize;
  uint32_t FileChecksum;
  uint16_t SubSystem;
  uint16_t DLLFlags;
  uint32_t StackReserveSize;
  uint32_t StackCommitSize;
  uint32_t HeapReserveSize;
  uint32_t HeapCommitSize;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
}
head2_32_t;

typedef struct
{
  uint64_t ImageBase;
  uint32_t SectionAlign;
  uint32_t FileAlign;
  uint16_t OSMajor;
  uint16_t OSMinor;
  uint16_t ImageMajor;
  uint16_t ImageMinor;
  uint16_t SubSystMajor;
  uint16_t SubSystMinor;
  uint32_t Win32Version;
  uint32_t ImageSize;
  uint32_t HeaderSize;
  uint32_t FileChecksum;
  uint16_t SubSystem;
  uint16_t DLLFlags;
  uint64_t StackReserveSize;
  uint64_t StackCommitSize;
  uint64_t HeapReserveSize;
  uint64_t HeapCommitSize;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
}
head2_64_t;

typedef struct {
    uint32_t RVA;
    uint32_t size;
}
direntry_t;

typedef struct {
    direntry_t ExportTable;
    direntry_t ImportTable;
    direntry_t ResourceTable;
    direntry_t ExceptionTable;
    direntry_t CertTable;
    direntry_t RelocTable;
    direntry_t Debug;
    direntry_t Arch;
    direntry_t GlobalPtr;
    direntry_t TLSTable;
    direntry_t LoadConfig;
    direntry_t BoundImport;
    direntry_t IAT;
    direntry_t DelayImportDesc;
    direntry_t CLRRuntimeHeader;
    direntry_t Res1;
}
dirhead_t;

typedef struct
{
  int8 Name[8];
  uint32_t VirtualSize;
  uint32_t RVA;
  uint32_t PhysicalSize;
  uint32_t PhysicalOffset;
  uint32_t RelocPtr;
  uint32_t LineNumbPtr;
  uint16_t NReloc;
  uint16_t NLineNumb;
  uint32_t Flags;
}
peobj_t;

typedef struct
{
  uint32_t ImpFlags; //LookupTableRVA;
  uint32_t DateTime;
  uint16_t MajVer;
  uint16_t MinVer;
  uint32_t NameRVA;
  uint32_t ImpTabRVA;
}
idirent_t;

typedef struct
{
  uint32_t Flags;
  uint32_t DateTime;
  uint16_t MajVer;
  uint16_t MinVer;
  uint32_t NameRVA;
  uint32_t OrdinalBase;
  uint32_t NumEATEntries;
  uint32_t NumNamePtrs;
  uint32_t AddressTableRVA;
  uint32_t NamePtrTableRVA;
  uint32_t OrdinalTableRVA;
}
edirent_t;
#pragma pack(pop)

struct {
    FILE *f;
    uint32_t peofs;
    head1_t peh;
    int bit64;
    head2_32_t pe32;
    head2_64_t pe64;
    uint64_t base;
    dirhead_t dir;
    struct  {
        uint32_t ofs;
        uint32_t siz;
        uint32_t RVA;
    } imp, exp;
} g_info;

static void kerror(const char *fmt,...)
{
  va_list args;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit(1);
}

static void expinfo(void *d)
{
  int i;
  edirent_t *exp = d + g_info.dir.ExportTable.RVA - g_info.exp.RVA;
  int rva = g_info.exp.RVA;

  printf("\tExport Table:\n");
  printf("\t\tFlags:%08x\n", exp->Flags);
 // printf("\t\tDateTime:%s", ctime((time_t *) & (exp->DateTime)));
  printf("\t\tMajVer:%04x\n", exp->MajVer);
  printf("\t\tMinVer:%04x\n", exp->MinVer);
  //printf("%p/%x\n", d, rva);
  printf("\t\tNameRVA:%08x (%s)\n", exp->NameRVA,
         (char *) d + exp->NameRVA - rva);
  printf("\t\tOrdinalBase:%08x\n", exp->OrdinalBase);
  printf("\t\tNumEATEntries:%08x\n", exp->NumEATEntries);
  printf("\t\tNumNamePtrs:%08x\n", exp->NumNamePtrs);
  printf("\t\tAddressTableRVA:%08x\n", exp->AddressTableRVA);
  printf("\t\tNamePtrTableRVA:%08x\n", exp->NamePtrTableRVA);
  printf("\t\tOrdinalTableRVA:%08x\n", exp->OrdinalTableRVA);

  if (exp->NumEATEntries != exp->NumNamePtrs)
  {
      printf("\t\tunsupported export table(%x!=%x)\n",
             exp->NumEATEntries, exp->NumNamePtrs);
    return;
  }
  for (i = 0; i < exp->NumEATEntries; i++)
  {
    int ord = *((short *) (d + exp->OrdinalTableRVA - rva) + i);
    int sym = *((int *) (d + exp->NamePtrTableRVA - rva) + i);
    //int ofs = *((int *) (d + exp->AddressTableRVA - rva) + i);
    int ofs = *((int *) (d + exp->AddressTableRVA - rva) + ord);

    printf("\t\t\t%08lx: %s\n", ofs + g_info.base, (char *) d - rva + sym);
  }
}

static void impinfo(void *d)
{
  int i;
  idirent_t *imp;
  int rva = g_info.imp.RVA;

  printf("\tImport Table:\n");
  for (imp = d + g_info.dir.ImportTable.RVA - g_info.imp.RVA;
       imp->NameRVA; imp++)
  {
    printf("\t\tImpFlags:%08x\n", imp->ImpFlags);
    //printf("\t\tDateTime:%08x\n", imp->DateTime);
    //printf("\t\tMajVer:%04x\n", imp->MajVer);
    //printf("\t\tMinVer:%04x\n", imp->MinVer);
    printf("\t\tNameRVA:%08x (%s)\n", imp->NameRVA,
           (char *) d + imp->NameRVA - rva);
    printf("\t\tImpTabRVA:%08x\n", imp->ImpTabRVA);
    for (i = 0;; i++)
    {
      int ofs;
      int64_t sym;
      if (g_info.bit64)
      {
          ofs = imp->ImpTabRVA + i * 8;
          sym = *((int64_t *) (d + ofs - rva));
      }
      else
      {
          ofs = imp->ImpTabRVA + i * 4;
          sym = *((int *) (d + ofs - rva));
      }
#if 0
      //int sym = *((int *) (d + imp->LookupTableRVA - rva) + i);
      if ((!sym) != (!ofs))
          kerror("broken import table");
#endif
      if (!sym)
          break;
      if (sym > 0)
          printf("\t\t\t%08lx: %s\n", ofs + g_info.base, (char *) d - rva + sym + 2);
      else
          printf("\t\t\t%#lx: ???\n", sym & 0x7fffffff);
    }
    printf("\n");
  }
}

static void peoinf(peobj_t * p)
{
  char buf[0x10];
  int imp, exp, siz;

  memset(buf, 0, sizeof(buf));
  strncpy(buf, p->Name, 8);
  printf("object name: %s\n", buf);
  printf("\tVirtualSize: %x\n", p->VirtualSize);
  printf("\tRVA: %x (%lx)\n", p->RVA, p->RVA + g_info.base);
  printf("\tPhysicalSize: %x\n", p->PhysicalSize);
  printf("\tPhysicalOffset: %x\n", p->PhysicalOffset);
  imp = g_info.dir.ImportTable.RVA;
  siz = p->VirtualSize;
  if (imp >= p->RVA && imp < (p->RVA + siz))
      printf("\timport table here\n");
  exp = g_info.dir.ExportTable.RVA;
  if (exp >= p->RVA && exp < (p->RVA + siz))
      printf("\texport table here\n");
}

static void peinfo(void)
{
  fseek(g_info.f, peheadofs, SEEK_SET);
  fread(&g_info.peofs, 4, 1, g_info.f);
  printf("PE header @%x\n", g_info.peofs);
  fseek(g_info.f, g_info.peofs, SEEK_SET);
  fread(&g_info.peh, 1, sizeof(g_info.peh), g_info.f);
  if (g_info.peh.Magic != pemagic)
      kerror("bad magic(%x)", g_info.peh.Magic);
  g_info.bit64 = 0;
  if (g_info.peh.Magic2 == 0x10b)
  {
      g_info.bit64 = 0;
      printf("PE32");
  }
  else if (g_info.peh.Magic2 == 0x20b)
  {
      g_info.bit64 = 1;
      printf("PE32+");
  }
  else
      printf("unknown image");
  printf(" (");
  if (g_info.peh.CPUType == 0x8664)
      printf("x86-64");
  else if (g_info.peh.CPUType == 0x14c)
      printf("i386");
  else
      printf("unknown");
  printf(")\n");

  if (g_info.bit64)
  {
      fread(&g_info.pe64, 1, sizeof(g_info.pe64), g_info.f);
      g_info.base = g_info.pe64.ImageBase;
  }
  else
  {
      fread(&g_info.pe32, 1, sizeof(g_info.pe32), g_info.f);
      g_info.base = g_info.pe32.ImageBase;
  }

  fread(&g_info.dir, 1, sizeof(g_info.dir), g_info.f);


#define SHOWPE(pe)\
  printf("ImageBase:\t\t%lx\n", (uint64_t)g_info.pe.ImageBase); \
  printf("ImageSize:\t\t%x\n", g_info.pe.ImageSize); \
  printf("SectionAlign:\t\t%x\n", g_info.pe.SectionAlign); \
  printf("FileAlign:\t\t%x\n", g_info.pe.FileAlign); \
  printf("EntryPointRVA:\t\t%lx (%lx)\n",(uint64_t)g_info.peh.EntryPointRVA,(uint64_t)g_info.peh.EntryPointRVA+g_info.pe.ImageBase);\
  printf("ExportTableRVA:\t\t%lx (%lx)\n",(uint64_t)g_info.dir.ExportTable.RVA,(uint64_t)g_info.dir.ExportTable.RVA+g_info.pe.ImageBase);\
  printf("TotalExportDataSize:\t%x\n", g_info.dir.ExportTable.size);\
  printf("ImportTableRVA:\t\t%lx (%lx)\n",(uint64_t)g_info.dir.ImportTable.RVA,(uint64_t)g_info.dir.ImportTable.RVA+g_info.pe.ImageBase);\
  printf("TotalImportDataSize:\t%x\n", g_info.dir.ImportTable.size);

  if (g_info.bit64)
  {
      SHOWPE(pe64);
  }
  else
  {
      SHOWPE(pe32);
  }
}

static void objscan(void)
{
    int cnt;
    peobj_t peo;
    int tmp;

    g_info.imp.ofs = 0;
    g_info.exp.ofs = 0;

    for (cnt = 0; cnt < g_info.peh.Sections; cnt++)
    {
        fseek(g_info.f, g_info.peh.NTHdrSize + g_info.peofs + ((void*)&g_info.peh.Magic2 - (void*)&g_info.peh) + cnt * sizeof(peo),
              SEEK_SET);
        fread(&peo, 1, sizeof(peo), g_info.f);
        tmp = g_info.dir.ImportTable.RVA;
        if (tmp >= peo.RVA && tmp < (peo.RVA + peo.VirtualSize))
        {
            g_info.imp.ofs = peo.PhysicalOffset;
            g_info.imp.siz = peo.VirtualSize;
            g_info.imp.RVA = peo.RVA;
        }
        tmp = g_info.dir.ExportTable.RVA;
        if (tmp >= peo.RVA && tmp < (peo.RVA + peo.VirtualSize))
        {
            g_info.exp.ofs = peo.PhysicalOffset;
            g_info.exp.siz = peo.VirtualSize;
            g_info.exp.RVA = peo.RVA;
        }
    }
}

static void objinfo(void)
{
    int cnt;
    peobj_t peo;

    for (cnt = 0; cnt < g_info.peh.Sections; cnt++)
    {
        fseek(g_info.f, g_info.peh.NTHdrSize + g_info.peofs + ((void*)&g_info.peh.Magic2 - (void*)&g_info.peh) + cnt * sizeof(peo),
              SEEK_SET);
        fread(&peo, 1, sizeof(peo), g_info.f);
        peoinf(&peo);
    }
}

static void help(char *name)
{
  printf("usage:\t%s <windows executeble>\n", name);
  exit(1);
}

int main(int argc, char *argv[])
{
    int act = 0;
    enum {ACT_HELP = 1, ACT_EXPORT = 2, ACT_IMPORT = 4, ACT_OBJECTS = 8};
    int c;


    while ((c = getopt(argc, argv, "heio")) != -1)
    {
        switch (c)
        {
        case 'h':
            act |= ACT_HELP;
            break;
        case 'e':
            act |= ACT_EXPORT;
            break;
        case 'i':
            act |= ACT_IMPORT;
            break;
        case 'o':
            act |= ACT_OBJECTS;
            break;
        default:
            act |= ACT_HELP;
            break;
        }
    }

    if (act & ACT_HELP)
    {
        help(argv[0]);
        return 1;
    }

    if (argc - optind < 1)
    {
        help(argv[0]);
        return 1;
    }

    printf("opening:%s\n",argv[optind]);

    if (!(g_info.f = fopen(argv[optind], "rb")))
    {
        perror(argv[optind]);
        return 1;
    }
    peinfo();
    if (act)
        objscan();
    if (act & ACT_EXPORT)
    {
        if (!g_info.exp.ofs)
            printf("can't find export table\n");
        else
        {
            uint8_t *data = malloc(g_info.exp.siz);
            fseek(g_info.f, g_info.exp.ofs, SEEK_SET);
            fread(data, 1, g_info.exp.siz, g_info.f);
            expinfo(data);
            free(data);
        }
    }
    if (act & ACT_IMPORT)
    {
        if (!g_info.imp.ofs)
            printf("can't find import table\n");
        else
        {
            uint8_t *data = malloc(g_info.imp.siz);
            fseek(g_info.f, g_info.imp.ofs, SEEK_SET);
            fread(data, 1, g_info.imp.siz, g_info.f);
            impinfo(data);
            free(data);
        }
    }
    if (act & ACT_OBJECTS)
        objinfo();


    fclose(g_info.f);

    return 0;
}
