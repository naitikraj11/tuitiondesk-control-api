create table if not exists public.client_registry (
  client_id text primary key,
  org text not null,
  username text not null unique,
  salt text not null,
  password_hash text not null,
  phone text,
  created_at timestamptz not null default now(),
  active boolean not null default true
);

alter table public.client_registry enable row level security;
revoke all on table public.client_registry from anon, authenticated;
grant all on table public.client_registry to service_role;
