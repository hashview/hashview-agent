require 'securerandom'
require 'json'
desc 'Setup remote agent'
  task :provision_remote_agent do
    if ENV['RACK_ENV'].nil?
      ENV['RACK_ENV'] = 'development'
    end

    puts "setting up remote agent for environment: #{ENV['RACK_ENV']}"

    agent_config = {}
    agent_config['master_ip'] = '192.168.0.253'
    agent_config['port'] = '4567'
    agent_config['uuid'] = SecureRandom.uuid.to_s
    File.open('config/agent_config.json', 'w') do |f|
      f.write(JSON.pretty_generate(agent_config))
    end

    puts 'db:provision_agent executed'
  end
