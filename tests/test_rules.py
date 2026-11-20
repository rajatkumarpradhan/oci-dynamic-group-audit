import unittest

from dg_audit.model import DynamicGroup, Export
from dg_audit.rules import (
    exit_code,
    rule_empty_membership,
    rule_tenancy_wide,
    rule_undocumented,
    rule_unreferenced,
    run_all,
)


def dg(name="g", desc="d", rule="all {instance.compartment.id = 'ocid1.compartment.oc1..c'}", matched=3):
    return DynamicGroup(ocid="ocid1.dynamicgroup.oc1..x", name=name, description=desc,
                        matching_rule=rule, matched_count=matched)


def exp(groups, statements=("Allow dynamic-group g to read x in compartment c",)):
    return Export(dynamic_groups=tuple(groups), policy_statements=tuple(statements))


class TestDg001(unittest.TestCase):
    def test_fires_on_tenancy_id(self):
        out = rule_tenancy_wide(exp([dg(rule="all {instance.tenancy.id = 'ocid1.tenancy..'}")]))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_fires_without_qualifier(self):
        out = rule_tenancy_wide(exp([dg(rule="all {resource.type = 'instance'}")]))
        self.assertEqual(len(out), 1)

    def test_quiet_compartment_scoped(self):
        self.assertEqual(rule_tenancy_wide(exp([dg()])), [])

    def test_case_insensitive(self):
        out = rule_tenancy_wide(exp([dg(rule="ALL {INSTANCE.TENANCY.ID = 'x'}")]))
        self.assertEqual(len(out), 1)


class TestDg002(unittest.TestCase):
    def test_fires_blank_description(self):
        self.assertEqual(len(rule_undocumented(exp([dg(desc="  ")]))), 1)

    def test_quiet_with_description(self):
        self.assertEqual(rule_undocumented(exp([dg()])), [])


class TestDg003(unittest.TestCase):
    def test_fires_unreferenced(self):
        out = rule_unreferenced(exp([dg(name="ghost-group")]))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "MEDIUM")

    def test_quiet_referenced(self):
        self.assertEqual(rule_unreferenced(exp([dg(name="g")])), [])

    def test_reference_case_insensitive(self):
        self.assertEqual(rule_unreferenced(exp([dg(name="G")], statements=("allow dynamic-group G to read x",))), [])


class TestDg004(unittest.TestCase):
    def test_fires_zero_matched(self):
        out = rule_empty_membership(exp([dg(matched=0)]))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "LOW")

    def test_quiet_nonempty(self):
        self.assertEqual(rule_empty_membership(exp([dg(matched=2)])), [])


class TestAggregation(unittest.TestCase):
    def test_exit_2_on_high(self):
        self.assertEqual(exit_code(run_all(exp([dg(rule="all {resource.type = 'instance'}")]))), 2)

    def test_exit_1_medium_only(self):
        self.assertEqual(exit_code(run_all(exp([dg(name="zzz", matched=2)]))), 1)

    def test_exit_0_clean(self):
        self.assertEqual(exit_code(run_all(exp([dg(name="g")]))), 0)

    def test_sorted_high_first(self):
        findings = run_all(exp([dg(name="zzz", rule="all {resource.type = 'instance'}", matched=0, desc="")]))
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "LOW")


if __name__ == "__main__":
    unittest.main()
