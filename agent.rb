require 'resque'

# simple config sanity checks

options = JSON.parse(File.read('config/agent_config.json'))

if options['hc_binary_path'].empty?
  puts '[!] You must defined the full path to your hashcat binary. Do this in your config/agent_config.json file'
  exit 0
end

if options['type'] == 'slave' && options['master_ip'] == '1.1.1.1'
  puts '[!] You must specify a valid IP to your master instance of Hashview. Do this in your config/agent_config.json file'
  exit 0
end

require_relative 'background_worker'

# run the agent
RemoteAgent
