require 'securerandom'
require 'json'
desc 'Setup remote agent'
  task :provision_remote_agent do
    if ENV['RACK_ENV'].nil?
      ENV['RACK_ENV'] = 'development'
    end

    puts "setting up remote agent for environment: #{ENV['RACK_ENV']}"

    agent_config = {}
    agent_config['master_ip'] = '1.1.1.1'
    agent_config['port'] = '4567'
    agent_config['uuid'] = SecureRandom.uuid.to_s
    agent_config['hc_binary_path'] = ''
    agent_config['type'] = 'slave'
    File.open('config/agent_config.json', 'w') do |f|
      f.write(JSON.pretty_generate(agent_config))
    end

    puts 'provision_agent executed'
  end
