-- Make profile creation on signup idempotent.
--
-- If more than one trigger on auth.users inserts into public.profiles (for
-- example after a partially re-run 0001 migration), the second insert violates
-- profiles_pkey and Supabase aborts the whole signup with
-- "Database error saving new user". Skipping an existing row makes that harmless.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, nullif(new.raw_user_meta_data ->> 'display_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists auth_user_profile_after_insert on auth.users;
create trigger auth_user_profile_after_insert
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Backfill: users created while the trigger was failing have no profile row.
insert into public.profiles (id)
select u.id from auth.users u
where not exists (select 1 from public.profiles p where p.id = u.id)
on conflict (id) do nothing;
