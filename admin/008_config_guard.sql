-- 008: the update row can only point to our own APK bucket, must carry a SHA-256, and min_code cannot exceed latest_code.
create or replace function public.noor_config_guard() returns trigger language plpgsql as $$
begin
  if new.apk_url is not null and new.apk_url <> '' then
    if new.apk_url !~ '^https://mzrbmjknvvckygwrzpnc\.supabase\.co/storage/v1/object/public/noor-apk/[A-Za-z0-9._-]+\.apk(\?v=[0-9]+)?$' then
      raise exception 'apk_url must be a file in the noor-apk bucket' using errcode='22023'; end if;
    if new.apk_sha256 is null or new.apk_sha256 !~ '^[0-9a-fA-F]{64}$' then
      raise exception 'apk_sha256 (64 hex) is required when apk_url is set' using errcode='22023'; end if;
  end if;
  if coalesce(new.min_code,0) > coalesce(new.latest_code,0) then
    raise exception 'min_code cannot be higher than latest_code (users could never satisfy it)' using errcode='22023'; end if;
  return new;
end $$;
drop trigger if exists noor_config_guard on public.noor_config;
create trigger noor_config_guard before insert or update on public.noor_config for each row execute function public.noor_config_guard();
