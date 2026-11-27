-- 009 (NOT APPLIED): require a 2-step-verified session (aal2) for every admin action.
-- Apply ONLY after the admin account has enrolled TOTP and logged in with a code once, otherwise the admin is locked out.
-- Recovery if locked out: delete the row for the user in auth.mfa_factors (SQL editor) and drop these policies.
create policy noor_installs_mfa on public.noor_installs as restrictive for all to authenticated using ((select auth.jwt()->>'aal') = 'aal2');
create policy noor_errors_mfa   on public.noor_errors   as restrictive for all to authenticated using ((select auth.jwt()->>'aal') = 'aal2');
create policy noor_config_mfa   on public.noor_config   as restrictive for all to authenticated using ((select auth.jwt()->>'aal') = 'aal2') with check ((select auth.jwt()->>'aal') = 'aal2');
create policy noor_messages_mfa on public.noor_messages as restrictive for all to authenticated using ((select auth.jwt()->>'aal') = 'aal2') with check ((select auth.jwt()->>'aal') = 'aal2');
create policy noor_apk_mfa on storage.objects as restrictive for all to authenticated using (bucket_id <> 'noor-apk' or (select auth.jwt()->>'aal') = 'aal2') with check (bucket_id <> 'noor-apk' or (select auth.jwt()->>'aal') = 'aal2');
