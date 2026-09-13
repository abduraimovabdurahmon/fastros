"""SMP topology discovery (phase 0).

The kernel parses the ACPI MADT to learn how many CPUs the platform has and the
LAPIC/IOAPIC addresses. This step is read-only — the application processors stay
parked until a later phase — so the system still runs on the boot CPU, but the
topology is now known and logged.
"""
import re


def test_smp_topology_discovered(g):
    out = g.ok("dmesg")
    m = re.search(r"smp: (\d+) CPU\(s\) present", out)
    assert m, f"no SMP discovery line in dmesg:\n{out[-2000:]}"
    n = int(m.group(1))
    assert n >= 1, out
    # The QEMU dev VM is launched with 2 vCPUs, so discovery should see both.
    assert n >= 2, f"expected >=2 CPUs discovered, got {n}"
    assert "LAPIC @" in out


def test_system_stable_with_multiple_cpus(g):
    """With extra vCPUs present (parked), the boot CPU still serves normally."""
    assert g.ok("uname -s").strip() == "FastROS", g.ok("uname -s")
    # A quick round trip proving the scheduler/IO path is healthy.
    assert g.ok("echo smp-ok").strip() == "smp-ok"
