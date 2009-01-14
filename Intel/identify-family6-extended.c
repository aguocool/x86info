/*
 *  (C) 2001,2008 Dave Jones.
 *
 *  Licensed under the terms of the GNU GPL License version 2.
 *
 *  Intel family 6 specific decoding (Core family).
 */

#include <stdio.h>
#include <string.h>
#include "../x86info.h"
#include "Intel.h"

static char *intel_nameptr;
#define add_to_cpuname(x)   intel_nameptr += snprintf(intel_nameptr, sizeof(x), "%s", x);

void Identify_Intel_family6core(struct cpudata *cpu)
{
	intel_nameptr = cpu->name;

	switch (model(cpu)) {
	case 7:
		switch (cpu->stepping) {
		case 6:
			// sSpec step CoreFreq Bus cache
			// SLAN3  C0  3.00    1333  12MB (2x6) QX9650
			// SLANY  C0  3.2     1600  12MB (2x6) QX9775
			add_to_cpuname("Core 2 quad ");
			switch (cpu->MHz) {
			case 3000:	add_to_cpuname("Core 2 quad (QX9650) ");
				break;
			case 3200:	add_to_cpuname("Core 2 Extreme quad (QX9775) ");
				break;
			}
			add_to_cpuname("[C0] ");
			break;
		case 7:
			// sSpec step CoreFreq Bus cache
			// SLAWM C1   3.2    1600  12MB (2x6)	QX9770
			// SLAWQ C1   2.83   1600  12MB (2x6)	Q9550
			// SLAWR C1   2.66   1333  12MB (2x6)	Q9450
			// SLAWE M1   2.50   1333  6MB (2x3)	Q9300
			// SLB5M M1   2.33   1333  4MB (2x2)    Q8200
			add_to_cpuname("Core 2 quad ");
			switch (cpu->MHz) {
			case 3200:	add_to_cpuname("(QX9770) [C1] ");
					break;
			case 2830:	add_to_cpuname("(Q9550) [C1] ");
					break;
			case 2660:	add_to_cpuname("(Q9450) [C1] ");
					break;
			case 2500:	add_to_cpuname("(Q9300) [M1] ");
					break;
			case 2330:	add_to_cpuname("(Q8200) [M1] ");
					break;
			}
			break;
		case 0xa:
			// sSpec step CoreFreq Bus cache
			// SLB8W E0  3.00     1333 12MB (2x6) Q9650
			// SLB8V E0  2.83     1333 12MB (2x6) Q9550
			// SLB6B R0  2.66     1333 6MB  (2x3) Q9400
			// SLB5W R0  2.5      1333 4MB  (2x2) Q8300
			add_to_cpuname("Core 2 quad ");
			switch (cpu->MHz) {
			case 3000:	add_to_cpuname("(Q9650) [E0] ");
					break;
			case 2830:	add_to_cpuname("(Q9550) [E0] ");
					break;
			case 2660:	add_to_cpuname("(Q9400) [R0] ");
					break;
			case 2500:	add_to_cpuname("(Q8300) [R0] ");
					break;
			}
			break;
		}
		break;
	case 0xa:
		add_to_cpuname("Core i7 ");
		//sSpec step CoreFreq/QuickpathGTs/DDR3	cache
		//SLBCJ C-0	3.2/6.40/1066		8MB
		//SLBCK C-0	2.93/4.80/1066		8MB
		//SLBCH C-0	2.66/4.80/1066		8MB
		break;
	case 0xe:
		add_to_cpuname("Core ");
		switch (cpu->stepping) {
		case 8:
			switch (cpu->MHz) {
			case 1000:
				// SL99W/SL8W7 533FSB
				add_to_cpuname("Duo U2400/Solo U1300 [C-0]");
				break;
			case 1200:
				// SL8W6 533FSB
				add_to_cpuname("Solo U1400 [C-0]");
				break;
			case 1500:
				// SL8VX 667FSB
				add_to_cpuname("Duo L2300 [C-0]");
				break;
			case 1600:
				// SL9JE/SL9JV/SL8VR/SL8VV/SL8VY/SL8W3/SL8VW 667FSB
				add_to_cpuname("Solo T1300/Duo T2300(E)/Duo L2400");
				break;
			case 1800:
				// SL92X/SL8VQ/SL8VU/SL92V/SL92X 667FSB
				add_to_cpuname("Solo T1400/Duo T2400 [C-0]");
				break;
			case 2000:
				// SL8VP/SL8VT/SL92U/SL92W 667FSB
				add_to_cpuname("Solo T1500/Duo T2500 [C-0]");
				break;
			case 2150:
				// SL8VN/SL8VS 667FSB
				add_to_cpuname("Duo T2600 [C-0]");
				break;
			}
			break;
		case 0xc:
			switch (cpu->MHz) {
			case 1200:
				// SL99V 533FSB
				add_to_cpuname("Duo U2500 [D-0]");
				break;
			case 1800:
				// SL9JU 667FSB
				add_to_cpuname("Duo L2500 [D-0]");
				break;
			case 2300:
				// SL9JP/SL9K4 667FSB
				add_to_cpuname("Duo T2700 [D-0]");
				break;
			}
		}
		break;

	case 23:
		add_to_cpuname("Core 2 Duo ");
		switch (cpu->stepping) {
		case 4:	add_to_cpuname("(Penryn)");
			break;
		case 6:	add_to_cpuname("P8600");
			break;
		}
		break;

	default:
                add_to_cpuname("Unknown model. ");
	}
}