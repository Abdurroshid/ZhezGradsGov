-- ============================================================================
--  Реестр аудита — схема базы данных Supabase (PostgreSQL)
--  Запустите этот файл целиком в Supabase → SQL Editor → New query → Run.
--  Он безопасен для повторного запуска (idempotent).
-- ============================================================================

-- ---------------------------------------------------------------------------
--  Таблицы
-- ---------------------------------------------------------------------------

-- Профиль организации. Привязан 1:1 к учётной записи в auth.users.
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  org_name   text not null,
  bin        text,
  email      text,
  role       text not null default 'org' check (role in ('org','admin')),
  created_at timestamptz not null default now()
);

-- Столбцы реестра (Бюджет, Код ДПД, Наименование КБК, Ожидаемая на, ...).
create table if not exists public.indicators (
  id         text primary key,
  name       text not null,
  unit       text not null default '',
  type       text not null default 'number' check (type in ('number','text')),
  sort_order int  not null default 0,
  created_at timestamptz not null default now()
);

-- Данные, поданные организацией. Одна строка на организацию, значения в JSON.
create table if not exists public.submissions (
  org_id     uuid primary key references auth.users(id) on delete cascade,
  values     jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
--  Вспомогательные функции
-- ---------------------------------------------------------------------------

-- Проверяет, является ли текущий пользователь аудитором (role = 'admin').
-- SECURITY DEFINER => обходит RLS таблицы profiles, чтобы не было рекурсии политик.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

-- При регистрации нового пользователя создаёт его профиль.
-- org_name и bin берутся из метаданных, переданных при signUp().
-- Строка в submissions не создаётся заранее — она появится при первом сохранении данных,
-- чтобы у ещё не подавшей отчёт организации статус был «Пока не сохранено».
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, org_name, bin, email, role)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data->>'org_name',''), 'Организация'),
    nullif(new.raw_user_meta_data->>'bin',''),
    new.email,
    'org'
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

-- Запрещает организации самой повысить себе роль до admin через update профиля.
create or replace function public.prevent_role_escalation()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- auth.uid() = NULL означает доверенный контекст (SQL Editor / service_role),
  -- где назначение роли аудитора разрешено. Блокируем только вошедших не-админов.
  if new.role is distinct from old.role
     and auth.uid() is not null
     and not public.is_admin() then
    new.role := old.role;
  end if;
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
--  Триггеры
-- ---------------------------------------------------------------------------

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

drop trigger if exists trg_prevent_role_escalation on public.profiles;
create trigger trg_prevent_role_escalation
  before update on public.profiles
  for each row execute function public.prevent_role_escalation();

-- ---------------------------------------------------------------------------
--  Row-Level Security  (главная защита — доступ проверяется в базе, а не в браузере)
-- ---------------------------------------------------------------------------

alter table public.profiles   enable row level security;
alter table public.indicators enable row level security;
alter table public.submissions enable row level security;

-- profiles: свой профиль видит владелец; все профили видит аудитор.
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select using ( id = auth.uid() or public.is_admin() );

drop policy if exists profiles_update_own on public.profiles;
create policy profiles_update_own on public.profiles
  for update using ( id = auth.uid() ) with check ( id = auth.uid() );

drop policy if exists profiles_delete_admin on public.profiles;
create policy profiles_delete_admin on public.profiles
  for delete using ( public.is_admin() );
-- INSERT в profiles делает только триггер handle_new_user (SECURITY DEFINER),
-- поэтому клиентской INSERT-политики нет.

-- submissions: свою строку видит и правит организация; все строки видит аудитор.
drop policy if exists submissions_select on public.submissions;
create policy submissions_select on public.submissions
  for select using ( org_id = auth.uid() or public.is_admin() );

drop policy if exists submissions_insert_own on public.submissions;
create policy submissions_insert_own on public.submissions
  for insert with check ( org_id = auth.uid() );

drop policy if exists submissions_update_own on public.submissions;
create policy submissions_update_own on public.submissions
  for update using ( org_id = auth.uid() ) with check ( org_id = auth.uid() );

drop policy if exists submissions_delete_admin on public.submissions;
create policy submissions_delete_admin on public.submissions
  for delete using ( public.is_admin() );

-- indicators: читают все вошедшие пользователи; меняет только аудитор.
drop policy if exists indicators_select_auth on public.indicators;
create policy indicators_select_auth on public.indicators
  for select using ( auth.uid() is not null );

drop policy if exists indicators_write_admin on public.indicators;
create policy indicators_write_admin on public.indicators
  for all using ( public.is_admin() ) with check ( public.is_admin() );

-- ---------------------------------------------------------------------------
--  Начальные столбцы реестра
-- ---------------------------------------------------------------------------

insert into public.indicators (id, name, unit, type, sort_order) values
  ('budget',   'Бюджет',            'тыс. ₸', 'number', 1),
  ('dpd_code', 'Код ДПД',           '',       'text',   2),
  ('kbk_name', 'Наименование КБК',  '',       'text',   3),
  ('expected', 'Ожидаемая на',      'тыс. ₸', 'number', 4)
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
--  Как назначить аудитора (admin)
--  1. Зарегистрируйтесь в приложении обычным способом под нужным email.
--  2. Затем выполните (подставьте свой email):
--
--     update public.profiles set role = 'admin'
--     where id = (select id from auth.users where email = 'admin@audit.gov.kz');
-- ---------------------------------------------------------------------------
