i18n = import('i18n')

desktop_file = i18n.merge_file(
  input: 'io.github.d3msudo.clamguard.desktop.in',
  output: 'io.github.d3msudo.clamguard.desktop',
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'applications'
)

metainfo_file = i18n.merge_file(
  input: 'io.github.d3msudo.clamguard.metainfo.xml.in',
  output: 'io.github.d3msudo.clamguard.metainfo.xml',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'metainfo'
)

install_data('io.github.d3msudo.clamguard.gschema.xml',
  install_dir: get_option('datadir') / 'glib-2.0' / 'schemas'
)

install_data('icons/hicolor/scalable/apps/io.github.d3msudo.clamguard.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'scalable' / 'apps'
)

install_data('systemd/clamguard-updater.service',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system')
install_data('systemd/clamguard-updater.timer',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system')
install_data('systemd/clamguard-scheduled-scan.service',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system')
install_data('systemd/clamguard-scheduled-scan.timer',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system')

configure_file(
  input: 'file-managers/nemo/clamguard-scan.nemo_action.in',
  output: 'clamguard-scan.nemo_action',
  copy: true,
  install: true,
  install_dir: get_option('datadir') / 'nemo' / 'actions',
)
install_data('file-managers/nautilus/clamguard_nautilus.py',
  install_dir: get_option('datadir') / 'nautilus-python' / 'extensions')
configure_file(
  input: 'file-managers/thunar/uca.xml.in',
  output: 'uca.xml',
  copy: true,
  install: true,
  install_dir: get_option('datadir') / 'thunar' / 'uca',
)
install_data('file-managers/dolphin/clamguard-scan.desktop',
  install_dir: get_option('datadir') / 'kservices5' / 'ServiceMenus')
