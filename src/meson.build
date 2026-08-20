python = import('python')
python_installation = python.find_installation('python3')

src_files = files(
  '__init__.py',
  'main.py',
  'window.py',
)

core_files = files(
  'core/__init__.py',
  'core/paths.py',
  'core/privileged_paths.py',
  'core/clamav.py',
  'core/freshclam.py',
  'core/third_party_db.py',
  'core/quarantine.py',
  'core/history.py',
  'core/virustotal.py',
  'core/eicar_helper.py',
)

# CG-013: chiave pubblica GPG bundled di sanesecurity. Installata come
# risorsa del pacchetto (canale di distribuzione separato dal feed), così
# la verifica GPG delle firme .sig può avvenire anche in Flatpak.
core_resources_files = files(
  'core/resources/sanesecurity.gpg',
)

daemon_files = files(
  'daemon/__init__.py',
  'daemon/cli.py',
  'daemon/updater_daemon.py',
  'daemon/scheduler_daemon.py',
)

cli_files = files(
  'cli/__init__.py',
  'cli/apply_signatures.py',
  'cli/install_helper.py',
)

cli_resources_files = files(
  'cli/resources/__init__.py',
  'cli/resources/io.github.d3msudo.clamguard.policy',
)

services_files = files(
  'services/__init__.py',
  'services/tray_service.py',
  'services/tray_manager.py',
  'services/clamd_service.py',
  'services/credentials.py',
  'services/polkit.py',
  'services/notifier.py',
)

ui_files = files(
  'ui/__init__.py',
)

ui_views_files = files(
  'ui/views/__init__.py',
)

ui_widgets_files = files(
  'ui/widgets/__init__.py',
)

install_data(src_files, install_dir: python_installation.get_install_dir() / 'clamguard')
install_data(core_files, install_dir: python_installation.get_install_dir() / 'clamguard/core')
install_data(core_resources_files, install_dir: python_installation.get_install_dir() / 'clamguard/core/resources')
install_data(daemon_files, install_dir: python_installation.get_install_dir() / 'clamguard/daemon')
install_data(cli_files, install_dir: python_installation.get_install_dir() / 'clamguard/cli')
install_data(cli_resources_files, install_dir: python_installation.get_install_dir() / 'clamguard/cli/resources')
install_data(services_files, install_dir: python_installation.get_install_dir() / 'clamguard/services')
install_data(ui_files, install_dir: python_installation.get_install_dir() / 'clamguard/ui')
install_data(ui_views_files, install_dir: python_installation.get_install_dir() / 'clamguard/ui/views')
install_data(ui_widgets_files, install_dir: python_installation.get_install_dir() / 'clamguard/ui/widgets')

# Binari lanciatori: senza questo, 'meson install' non produce alcun
# eseguibile in bindir e il pacchetto risulta inavviabile (né via
# Exec= nel .desktop, né via systemd, né via integrazioni file-manager).
launcher_conf = configuration_data()
launcher_conf.set('PYTHONDIR', python_installation.get_install_dir())
launcher_conf.set('VERSION', meson.project_version())

configure_file(
  input: 'clamguard.in',
  output: 'clamguard',
  configuration: launcher_conf,
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x',
)

configure_file(
  input: 'clamguard-daemon.in',
  output: 'clamguard-daemon',
  configuration: launcher_conf,
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x',
)
