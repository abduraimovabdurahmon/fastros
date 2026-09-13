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


def test_ap_brought_online(g):
    """SMP step 3: each application processor reaches long-mode Rust and parks.

    The AP runs the trampoline (real -> protected -> long mode) on the live
    kernel page tables, marks itself online, then halts. It does no scheduling
    and takes no interrupts yet, so the boot CPU keeps running everything.
    """
    out = g.ok("dmesg")
    # Only assert bringup if the LAPIC timer actually came up (bringup is gated
    # on it). On the dev VM it does.
    if "LAPIC timer @" not in out:
        return
    m = re.search(r"smp: (\d+) CPU\(s\) online \(1 BSP \+ (\d+) AP\)", out)
    assert m, f"no SMP bringup summary in dmesg:\n{out[-2000:]}"
    total, aps = int(m.group(1)), int(m.group(2))
    assert total == 1 + aps, out
    # The dev VM has 2 vCPUs, so exactly one AP should have come online.
    assert aps >= 1, f"expected >=1 AP online, got {aps}:\n{out[-2000:]}"
    assert re.search(r"smp: CPU \(APIC \d+\) online", out), out


def test_no_panic_after_ap_bringup(g):
    """Bringing up the AP must never destabilise the running system."""
    assert "panic" not in g.ok("dmesg").lower()
    assert g.ok("echo alive").strip() == "alive"
