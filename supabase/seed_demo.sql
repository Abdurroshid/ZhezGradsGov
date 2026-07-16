-- ============================================================================
--  Демо-данные для реестра аудита
--  Запустить ОДИН раз: Supabase → SQL Editor → New query → вставить → Run.
--
--  Что делает скрипт:
--    1. Подтверждает email аудитора и выдаёт ему роль admin.
--    2. Создаёт 8 демо-организаций (email уже подтверждён, пароль: demo123)
--       вместе с их поданными данными и разной степенью заполненности.
--
--  Скрипт можно запускать повторно: существующие организации пропускаются.
--  Пароли хешируются bcrypt через crypt() — как это делает сам Supabase Auth.
-- ============================================================================

-- ---------------------------------------------------------------------------
--  1. Аудитор (admin)
-- ---------------------------------------------------------------------------

update auth.users
set email_confirmed_at = coalesce(email_confirmed_at, now())
where email = 'abdurashidzhez+audit@gmail.com';

update public.profiles
set role = 'admin'
where id = (select id from auth.users where email = 'abdurashidzhez+audit@gmail.com');

-- ---------------------------------------------------------------------------
--  2. Демо-организации
-- ---------------------------------------------------------------------------

do $$
declare
  r   record;
  uid uuid;
begin
  for r in
    select * from (values
      ('office@zhezenergo.kz',       'АО «Жезказган Энерго»',                                  '020340001845',
       '{"budget":"4215600","dpd_code":"001","kbk_name":"Коммунальные услуги","expected":"3980000"}'::jsonb, 1),

      ('info@su-arnasy.kz',          'КГП «Жезказган Су Арнасы»',                              '991140002317',
       '{"budget":"987300","dpd_code":"003","kbk_name":"Текущий ремонт зданий и сооружений","expected":"910500"}'::jsonb, 2),

      ('zakup@sarystroy.kz',         'ТОО «СарыАрка СтройМонтаж»',                             '120540003692',
       '{"budget":"1264800","dpd_code":"015","kbk_name":"Приобретение основных средств"}'::jsonb, 3),

      ('dispatch@ulytau-trans.kz',   'ТОО «Улытау Транс Логистик»',                            '150940004518',
       '{"budget":"645200","dpd_code":"007","expected":"602000"}'::jsonb, 5),

      ('buh@zheznan.kz',             'ТОО «Жезқазған Нан»',                                    '080240001126',
       '{"budget":"312400","dpd_code":"225","kbk_name":"Приобретение материалов","expected":"298700"}'::jsonb, 0),

      ('a.abdrahmanova@mail.kz',     'ИП «Абдрахманова А.К.»',                                 '870615400921',
       '{"budget":"24850","dpd_code":"149"}'::jsonb, 4),

      ('cbs.zhez@gov.kz',            'КГУ «Централизованная библиотечная система г. Жезказган»','000940005274',
       '{"dpd_code":"001","kbk_name":"Услуги связи"}'::jsonb, 6),

      ('reception@medfarm-zhez.kz',  'ТОО «МедФарм Жезказган»',                                '190140006833',
       '{}'::jsonb, 1)
    ) as t(email, org_name, bin, vals, days_ago)
  loop
    -- уже создана — пропускаем
    if exists (select 1 from auth.users where email = r.email) then
      continue;
    end if;

    uid := gen_random_uuid();

    -- Учётная запись входа. email_confirmed_at = now() => подтверждение не требуется.
    insert into auth.users (
      instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, email_change, email_change_token_new, recovery_token
    ) values (
      '00000000-0000-0000-0000-000000000000', uid, 'authenticated', 'authenticated',
      r.email,
      crypt('demo123', gen_salt('bf')),
      now(),
      '{"provider":"email","providers":["email"]}'::jsonb,
      jsonb_build_object('org_name', r.org_name, 'bin', r.bin),
      now() - ((r.days_ago + 1) * interval '1 day'),
      now(),
      '', '', '', ''
    );

    -- Identity для email-провайдера (создаётся Supabase при обычной регистрации).
    insert into auth.identities (
      provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at
    ) values (
      uid::text, uid,
      jsonb_build_object('sub', uid::text, 'email', r.email, 'email_verified', true, 'phone_verified', false),
      'email', now(), now(), now()
    );

    -- Профиль создаётся автоматически триггером handle_new_user.
    -- Поданные данные добавляем только тем, у кого они есть,
    -- чтобы у остальных статус остался «Пока не сохранено».
    if r.vals <> '{}'::jsonb then
      insert into public.submissions (org_id, "values", updated_at)
      values (uid, r.vals, now() - (r.days_ago * interval '1 day') - interval '3 hours')
      on conflict (org_id) do update
        set "values" = excluded."values", updated_at = excluded.updated_at;
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------------
--  Проверка результата
-- ---------------------------------------------------------------------------

select p.org_name, p.email, p.role, p.bin,
       (select count(*) from jsonb_object_keys(coalesce(s."values", '{}'::jsonb))) as filled_columns
from public.profiles p
left join public.submissions s on s.org_id = p.id
order by p.role desc, p.org_name;
