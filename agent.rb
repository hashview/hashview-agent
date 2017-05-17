require 'resque'
require_relative 'background_worker'

# simple config sanity checks

options = JSON.parse(File.read('config/agent_config.json'))

if options['hc_binary_path'] == nil
  puts '[!] You must defined the full path to your hashcat binary'
end

if options['type'] == 'slave' && options['master'] == '1.1.1.1'
  puts '[!] You must specify a valid IP to your master instance of Hashview'
end

# run the agent
RemoteAgent
