"""Supabase RLS / data-privacy adapter package (Phase 08).

Like the cross-stack SCA package (Phase 7) and UNLIKE ``typescript-node``,
this package's ``@register_adapter('supabase')`` side-effect + the
``run_supabase`` collection entry point land in Plan 05 — NOT here. Plan 01
(this plan) ships only the shared CRIT-4 tripwire
(:mod:`repo_audit.adapters.supabase.verify_phrasing`) that every Wave 1
static/heuristic collector routes its findings through.

Wave 1 collectors (Plans 02-04) drop in alongside this module:
    * ephemeral-Postgres lifecycle + splinter row-mapper (Plan 02)
    * pgrls SARIF + squawk migration-safety (Plan 03)
    * RLS-04 footguns + the gated two-account runtime probe (Plan 04)
"""
