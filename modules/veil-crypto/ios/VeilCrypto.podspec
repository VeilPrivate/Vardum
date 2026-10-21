require 'json'

package = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'VeilCrypto'
  s.version        = package['version']
  s.summary        = package['description']
  s.description    = package['description']
  s.license        = 'Proprietary'
  s.author         = 'Vardum'
  s.homepage       = 'https://veil.privacy'
  s.platforms      = { :ios => '15.1' }
  s.source         = { :git => '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.source_files = '**/*.{h,m,mm,swift,hpp,cpp}'
end
