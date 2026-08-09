project('clamguard',
  version: '0.1.0',
  meson_version: '>= 1.0.0',
  default_options: ['warning_level=2', 'werror=false'],
)

python = import('python')
python_installation = python.find_installation('python3', required: true)

# Dependencies
dependency('gtk4', version: '>= 4.10')
dependency('libadwaita-1', version: '>= 1.4')

# Directories
prefix = get_option('prefix')
bindir = get_option('bindir')
datadir = get_option('datadir')
localedir = get_option('localedir')
pkgdatadir = datadir / meson.project_name()

# Configuration
conf = configuration_data()
conf.set('VERSION', meson.project_version())
conf.set('APP_ID', 'io.github.d3msudo.clamguard')
conf.set('PKGDATADIR', pkgdatadir)
conf.set('LOCALEDIR', localedir)
conf.set('PYTHON', python_installation.full_path())

# Subdirectories
subdir('data')
subdir('po')
subdir('src')
subdir('tests')

# Summary
summary('Prefix', prefix)
summary('Bindir', bindir)
summary('Datadir', datadir)
summary('Python', python_installation.full_path())
