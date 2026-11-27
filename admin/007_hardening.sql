-- 007: backend hardening (no behavior change for the app or the admin)
-- 1) TRUNCATE/REFERENCES/TRIGGER ignore RLS. Nobody but the owner role needs them.
do $$ declare t record; begin
  for t in select tablename from pg_tables where schemaname='public' loop
    execute format('revoke truncate, references, trigger on public.%I from anon, authenticated', t.tablename);
  end loop; end $$;
-- 2) flood guards on the two public write endpoints
create or replace function public.noor_ping_guard() returns boolean language sql stable security definer set search_path=public as $$
  select (select count(*) from public.noor_installs where first_seen > now() - interval '1 hour') < 3000 $$;
revoke all on function public.noor_ping_guard() from public, anon, authenticated;

create or replace function public.noor_report_error(
  p_install uuid, p_name text, p_code int, p_android text, p_model text, p_summary text, p_trace text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p_install is null then return; end if;
  -- only known installs may report; per-install cap 10/day; global cap 400/hour
  if not exists (select 1 from public.noor_installs where install_id = p_install) then return; end if;
  if (select count(*) from public.noor_errors where install_id = p_install and created_at > now() - interval '1 day') >= 10 then return; end if;
  if (select count(*) from public.noor_errors where created_at > now() - interval '1 hour') >= 400 then return; end if;
  insert into public.noor_errors(install_id, version_name, version_code, android, model, summary, trace)
  values (p_install, left(p_name,20), p_code, left(p_android,20), left(p_model,60), left(p_summary,300), left(p_trace,6000));
end $$;

CREATE OR REPLACE FUNCTION public.noor_ping(p_install uuid, p_name text, p_code integer, p_android text, p_model text, p_lang text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare c public.noor_config; msgs jsonb; fs timestamptz; cc text;
begin
  if p_install is null or p_code is null or p_code < 0 or p_code > 1000000 then return '{}'::jsonb; end if;
  -- country from the CDN header only (the IP itself is never read or stored)
  begin
    cc := upper(coalesce(nullif(current_setting('request.headers', true),'')::jsonb->>'cf-ipcountry',''));
  exception when others then cc := null; end;
  if cc is null or cc !~ '^[A-Z]{2}$' or cc in ('XX','T1') then cc := null; end if;
  -- flood guard: brand-new installs are accepted up to 3000/hour; known installs are never blocked
  if not exists (select 1 from public.noor_installs where install_id = p_install) and not public.noor_ping_guard() then
    select * into c from public.noor_config where id = 1;
    return jsonb_build_object('latest_code', c.latest_code, 'latest_name', c.latest_name, 'min_code', c.min_code,
      'apk_url', c.apk_url, 'apk_sha256', c.apk_sha256, 'note_ar', c.note_ar, 'note_en', c.note_en, 'messages', '[]'::jsonb);
  end if;
  insert into public.noor_installs(install_id, version_name, version_code, android, model, lang, country)
  values (p_install, left(p_name,20), p_code, left(p_android,20), left(p_model,60), left(p_lang,8), cc)
  on conflict (install_id) do update set last_seen = now(),
    version_name = excluded.version_name, version_code = excluded.version_code,
    android = excluded.android, model = excluded.model, lang = excluded.lang,
    country = coalesce(excluded.country, public.noor_installs.country);
  select first_seen into fs from public.noor_installs where install_id = p_install;
  select * into c from public.noor_config where id = 1;
  select coalesce(jsonb_agg(jsonb_build_object('id', m.id, 'title', m.title, 'body', m.body) order by m.id), '[]'::jsonb)
    into msgs from public.noor_messages m
    where m.active and m.starts_at <= now() and (m.expires_at is null or m.expires_at > now())
      and fs <= greatest(m.starts_at, m.created_at);
  return jsonb_build_object(
    'latest_code', c.latest_code, 'latest_name', c.latest_name, 'min_code', c.min_code,
    'apk_url', c.apk_url, 'apk_sha256', c.apk_sha256, 'note_ar', c.note_ar, 'note_en', c.note_en,
    'messages', msgs);
end $function$;
