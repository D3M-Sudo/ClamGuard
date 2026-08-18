test_clamav = find_program('python3')
test_src = meson.project_source_root() / 'tests'
test_workdir = meson.project_source_root()

# unittest discover assumes a package structure; '-s' is the start dir,
# '-p' the pattern. workdir is set to the project root so that the
# tests can `import src.core...`.
test('clamav_parser', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_clamav_parser.py'],
     workdir: test_workdir)
test('quarantine', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_quarantine.py'],
     workdir: test_workdir)
test('third_party', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_third_party_updater.py'],
     workdir: test_workdir)
test('virustotal', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_virustotal.py'],
     workdir: test_workdir)
test('eicar', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_eicar.py'],
     workdir: test_workdir)
test('tray_manager', test_clamav,
     args: ['-m', 'unittest', 'discover', '-s', test_src, '-p', 'test_tray_manager.py'],
     workdir: test_workdir)
