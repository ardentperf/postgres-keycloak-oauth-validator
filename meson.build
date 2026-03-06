project(
    'postgres-entra-oauth-validator', 'c',
    license: 'Apache-2.0',
    license_files: 'LICENSE',
    version: '0.0.1')

# pg_config command is required to get the include directory for
# the headers
pg_config = find_program('pg_config')
includedir_server = run_command(pg_config, '--includedir-server', check: true).stdout().strip()

# PostgreSQL is required for standard build
postgres = dependency('libpq')

# The library is built as a shared object since it's going to be
# loaded into PostgreSQL later as an extension.
# Setting the prefix to '' avoids a `lib` prefix on the final file.
shared_module('entra_validator', 'src/entra_validator.c',
              dependencies: [postgres],
              include_directories: [includedir_server],
              name_prefix: '')
