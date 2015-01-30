use inc::Module::Install;

RTx 'RT-Extension-FutureMailgate';

requires 'Role::Basic';
requires 'Scope::Upper';

requires_rt '4.0';
rt_too_new '4.4';

perl_version '5.010001';

sign;
WriteAll;
