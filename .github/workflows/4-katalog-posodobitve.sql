-- =====================================================================
-- Primož App – katalog vozil in varne spletne posodobitve
-- Za obstoječi projekt poženi po 1-schema.sql, 2-admin.sql in 3-zascita-podpisa.sql.
-- Skripta je idempotentna. Tabele niso neposredno dostopne prek Data API.
-- =====================================================================

create table if not exists public.vehicle_catalog (
  id text primary key check (length(id) between 1 and 80),
  brand text not null check (length(brand) between 1 and 120),
  model text not null check (length(model) between 1 and 160),
  engine_capacity text not null default '', engine_name text not null default '', engine_code text not null default '',
  fuel text not null default '', power text not null default '', period text not null default '',
  engine_oil_spec text not null default '', engine_oil_capacity text not null default '', coolant text not null default '',
  brake_fluid text not null default '', transmission_oil text not null default '', ac_refrigerant text not null default '',
  known_faults text not null default '', recalls text not null default '', tsb text not null default '',
  tyre_pressure text not null default '', tyre_sizes text not null default '', sources text not null default '',
  row_status text not null default '', verified_fields text not null default '', conditional_fields text not null default '',
  warnings text not null default '', imported_at timestamptz not null default now()
);
create index if not exists vehicle_catalog_lookup on public.vehicle_catalog (lower(brand), lower(model));

create table if not exists public.vehicle_catalog_imports (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  state text not null default 'open' check (state in ('open','committed')),
  created_at timestamptz not null default now(), committed_at timestamptz
);
create table if not exists public.vehicle_catalog_stage (
  batch_id uuid not null references public.vehicle_catalog_imports(id) on delete cascade,
  id text not null, row_data jsonb not null,
  primary key (batch_id, id)
);

create table if not exists public.app_updates (
  id bigint generated always as identity primary key,
  app text not null check (app in ('app','admin')),
  version text not null check (version ~ '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$'),
  url text not null check (url ~ '^https://'), checksum text check (checksum is null or checksum ~ '^[0-9a-fA-F]{64}$'),
  notes text not null default '', active boolean not null default true,
  published_at timestamptz not null default now(), unique (app, version)
);
create index if not exists app_updates_latest on public.app_updates (app, active, published_at desc);

do $$
declare t text;
begin
  foreach t in array array['vehicle_catalog','vehicle_catalog_imports','vehicle_catalog_stage','app_updates'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from public, anon, authenticated', t);
  end loop;
end $$;

create or replace function public.app_catalog_search(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_ok boolean; v_err text; v_dev_status text; v_acc_disabled boolean; v_data jsonb;
        v_q text; v_limit int;
begin
  select ok, err, (dev).status, (acc).disabled, data
    into v_ok, v_err, v_dev_status, v_acc_disabled, v_data
    from app_private.verify(p_payload, p_sig, 'catalog_search');
  if not v_ok then return jsonb_build_object('ok', false, 'error', v_err); end if;
  if v_acc_disabled or v_dev_status <> 'active' or (select locked from app_config where id=1) then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  v_q := left(trim(coalesce(v_data->>'q','')), 100);
  v_limit := least(greatest(coalesce((v_data->>'limit')::int, 12), 1), 20);
  if v_q = '' then return jsonb_build_object('ok', true, 'items', '[]'::jsonb); end if;
  return jsonb_build_object('ok', true, 'items', coalesce((
    select jsonb_agg(to_jsonb(c) - 'imported_at' order by
      case when c.brand ilike v_q || '%' then 0 when c.model ilike v_q || '%' then 1 else 2 end,
      c.brand, c.model, c.engine_name)
    from (select * from vehicle_catalog
          where brand ilike '%' || v_q || '%' or model ilike '%' || v_q || '%'
             or engine_name ilike '%' || v_q || '%' or engine_code ilike '%' || v_q || '%'
          limit v_limit) c), '[]'::jsonb));
exception when invalid_text_representation then
  return jsonb_build_object('ok', false, 'error', 'bad_request');
end $$;

create or replace function public.admin_catalog_status()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  perform app_private.require_admin();
  return jsonb_build_object('count', (select count(*) from vehicle_catalog),
    'updated_at', (select max(imported_at) from vehicle_catalog));
end $$;

create or replace function public.admin_catalog_begin()
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  perform app_private.require_admin();
  delete from vehicle_catalog_imports where state='open' and created_at < now() - interval '24 hours';
  insert into vehicle_catalog_imports(owner) values(auth.uid()) returning id into v_id;
  return jsonb_build_object('batch', v_id);
end $$;

create or replace function public.admin_catalog_chunk(p_batch uuid, p_rows jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r jsonb; v_count int := 0;
begin
  perform app_private.require_admin();
  if not exists(select 1 from vehicle_catalog_imports where id=p_batch and owner=auth.uid() and state='open') then
    raise exception 'bad_batch' using errcode='22023';
  end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) < 1 or jsonb_array_length(p_rows) > 100 then
    raise exception 'bad_rows' using errcode='22023';
  end if;
  for r in select value from jsonb_array_elements(p_rows) loop
    if length(trim(coalesce(r->>'id',''))) not between 1 and 80
       or length(trim(coalesce(r->>'brand',''))) not between 1 and 120
       or length(trim(coalesce(r->>'model',''))) not between 1 and 160
       or pg_column_size(r) > 100000 then
      raise exception 'bad_row' using errcode='22023';
    end if;
    insert into vehicle_catalog_stage(batch_id,id,row_data)
      values(p_batch, trim(r->>'id'), r)
      on conflict(batch_id,id) do update set row_data=excluded.row_data;
    v_count := v_count + 1;
  end loop;
  return jsonb_build_object('ok', true, 'received', v_count);
end $$;

create or replace function public.admin_catalog_commit(p_batch uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare v_count int;
begin
  perform app_private.require_admin();
  if not exists(select 1 from vehicle_catalog_imports where id=p_batch and owner=auth.uid() and state='open' for update) then
    raise exception 'bad_batch' using errcode='22023';
  end if;
  select count(*) into v_count from vehicle_catalog_stage where batch_id=p_batch;
  if v_count < 1 then raise exception 'empty_catalog' using errcode='22023'; end if;
  delete from vehicle_catalog;
  insert into vehicle_catalog(id,brand,model,engine_capacity,engine_name,engine_code,fuel,power,period,
    engine_oil_spec,engine_oil_capacity,coolant,brake_fluid,transmission_oil,ac_refrigerant,known_faults,
    recalls,tsb,tyre_pressure,tyre_sizes,sources,row_status,verified_fields,conditional_fields,warnings)
  select id, trim(row_data->>'brand'), trim(row_data->>'model'), coalesce(row_data->>'engine_capacity',''),
    coalesce(row_data->>'engine_name',''),coalesce(row_data->>'engine_code',''),coalesce(row_data->>'fuel',''),
    coalesce(row_data->>'power',''),coalesce(row_data->>'period',''),coalesce(row_data->>'engine_oil_spec',''),
    coalesce(row_data->>'engine_oil_capacity',''),coalesce(row_data->>'coolant',''),coalesce(row_data->>'brake_fluid',''),
    coalesce(row_data->>'transmission_oil',''),coalesce(row_data->>'ac_refrigerant',''),coalesce(row_data->>'known_faults',''),
    coalesce(row_data->>'recalls',''),coalesce(row_data->>'tsb',''),coalesce(row_data->>'tyre_pressure',''),
    coalesce(row_data->>'tyre_sizes',''),coalesce(row_data->>'sources',''),coalesce(row_data->>'row_status',''),
    coalesce(row_data->>'verified_fields',''),coalesce(row_data->>'conditional_fields',''),coalesce(row_data->>'warnings','')
  from vehicle_catalog_stage where batch_id=p_batch;
  update vehicle_catalog_imports set state='committed', committed_at=now() where id=p_batch;
  perform app_private.log_event('catalog_imported','info',null,null,'',jsonb_build_object('rows',v_count));
  return jsonb_build_object('ok', true, 'count', v_count);
end $$;

create or replace function public.app_latest_update(p_app text, p_version text)
returns jsonb language sql stable security definer set search_path = public as $$
  select case when u.id is null then null else jsonb_strip_nulls(jsonb_build_object(
    'version',u.version,'url',u.url,'checksum',u.checksum,'notes',u.notes)) end
  from (select * from app_updates where app=p_app and active and version<>coalesce(p_version,'')
        order by published_at desc limit 1) u
  right join (select 1) x on true
$$;

revoke all on function public.app_catalog_search(text,text) from public,anon,authenticated;
revoke all on function public.admin_catalog_status() from public,anon,authenticated;
revoke all on function public.admin_catalog_begin() from public,anon,authenticated;
revoke all on function public.admin_catalog_chunk(uuid,jsonb) from public,anon,authenticated;
revoke all on function public.admin_catalog_commit(uuid) from public,anon,authenticated;
revoke all on function public.app_latest_update(text,text) from public,anon,authenticated;
grant execute on function public.app_catalog_search(text,text) to anon,authenticated;
grant execute on function public.app_latest_update(text,text) to anon,authenticated;
grant execute on function public.admin_catalog_status() to authenticated;
grant execute on function public.admin_catalog_begin() to authenticated;
grant execute on function public.admin_catalog_chunk(uuid,jsonb) to authenticated;
grant execute on function public.admin_catalog_commit(uuid) to authenticated;

notify pgrst, 'reload schema';
