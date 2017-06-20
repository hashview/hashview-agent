require 'rest-client'
require 'benchmark'

$hashcatbinpath = JSON.parse(File.read('config/agent_config.json'))['hc_binary_path']

# one day, when I grow up...I'll be a ruby dev
# api calls
class Api

  # obtain remote ip and port from local config
  begin
    options = JSON.parse(File.read('config/agent_config.json'))
    @server = options['master_ip'] + ":" + options['port']
    @uuid = options['uuid']
    @hashcatbinpath = options['hc_binary_path']
  rescue
    "Error reading config/agent_config.json. Did you run rake db:provision_agent ???"
  end

  ######### generic api handling of GET and POST request ###########
  def self.get(url)
    begin
      response = RestClient::Request.execute(
          :method => :get,
          :url => url,
          :cookies => {:agent_uuid => @uuid},
          :verify_ssl => false
      )
      return response.body
    rescue RestClient::Exception => e
      puts e
      return '{"error_msg": "api call failed"}'
    rescue Errno::ECONNREFUSED => err
      puts err
      return '{"error_msg": "connection refused from remote host"}'
    end
  end

  def self.post(url, payload)
    begin
      response = RestClient::Request.execute(
          :method => :post,
          :url => url,
          :payload => payload.to_json,
          :headers => {:accept => :json},
          :cookies => {:agent_uuid => @uuid},
          :verify_ssl => false
      )
      return response.body
    rescue RestClient::Exception => e
      puts e
      return '{"error_msg": "api call failed"}'
    rescue Errno::ECONNREFUSED => err
      puts err
      return '{"error_msg": "connection refused from remote host"}'
    end
  end


  ######### specific api functions #############

  # post heartbeat is used when agent is working
  def self.post_heartbeat(payload)
    url = "https://#{@server}/v1/agents/#{@uuid}/heartbeat"
    puts "HEARTBEETING"
    return self.post(url, payload)
  end

  # change status of jobtask
  def self.post_jobtask_status(jobtask_id, status)
    url = "https://#{@server}/v1/jobtask/#{jobtask_id}/status"
    payload = {}
    payload['status'] = status
    payload['jobtask_id'] = jobtask_id
    return self.post(url, payload)
  end

  # change status of taskqueue item
  def self.post_queue_status(taskqueue_id, status)
    url = "https://#{@server}/v1/queue/#{taskqueue_id}/status"
    payload = {}
    payload['status'] = status
    payload['taskqueue_id'] = taskqueue_id
    payload['agent_uuid'] = @uuid
    return self.post(url, payload)
  end

  # get next item in queue
  def self.queue
    url = "https://#{@server}/v1/queue"
    return self.get(url)
  end

  # get specific item from queue (must already be assigned to agent)
  def self.queue_by_id(id)
    url = "https://#{@server}/v1/queue/#{id}"
    return self.get(url)
  end

    # remove item from queue
  def self.queue_remove(queue_id)
    url = "https://#{@server}/v1/queue/#{queue_id}/remove"
    return self.get(url)
  end

  # jobtask details
  def self.jobtask(jobtask_id)
    url = "https://#{@server}/v1/jobtask/#{jobtask_id}"
    return self.get(url)
  end

  # job details
  def self.job(job_id)
    url = "https://#{@server}/v1/job/#{job_id}"
    return self.get(url)
  end

  # download hashfile
  def self.hashfile(jobtask_id, hashfile_id)
    url = "https://#{@server}/v1/jobtask/#{jobtask_id}/hashfile/#{hashfile_id}"
    return self.get(url)
  end

  # Rules
  def self.rules()
    url = "https://#{@server}/v1/rules"
    return self.get(url)
  end

  # Download a rules file
  def self.rule(rules_id)
    url = "https://#{@server}/v1/rules/#{rules_id}"
    return self.get(url)
  end

  # wordlists
  def self.wordlists()
    url = "https://#{@server}/v1/wordlist"
    return self.get(url)
  end

  # # download a wordlist
  # def self.wordlist(wordlist_id)
  #   url = "https://#{@server}/v1/wordlist/#{wordlist_id}"
  #  return self.get(url)
  # end

  # # save wordlist to disk
  # def self.save_wordlist(localpath='control/wordlists/thisisjustatest.txt')
  #   File.write(localpath)
  # end

  # upload crack file
  def self.upload_crackfile(jobtask_id, crack_file, run_time)
    url = "https://#{@server}/v1/jobtask/#{jobtask_id}/crackfile/upload"
    puts "attempting upload #{crack_file}"
    begin
      request = RestClient::Request.new(
        :method => :post,
        :url => url,
        :payload => {
          :multipart => true,
          :file => File.new(crack_file, 'rb'),
          :runtime => run_time
        },
        :cookies => {:agent_uuid => @uuid},
        :verify_ssl => false
      )
      response = request.execute
    rescue RestClient::Exception => e
      puts e
      return '{error_msg: \'api call failed\'}'
    end
  end

  def self.stats(hc_devices, hc_perfstats)
    url = "https://#{@server}/v1/agents/#{@uuid}/stats"
    payload = {}
    payload['cpu_count'] = hc_devices['cpus']
    payload['gpu_count'] = hc_devices['gpus']
    payload['benchmark'] = hc_perfstats
    return self.post(url, payload)
  end
end

# parses hashcat output
def hashcatParser(filepath)
  status = {}
  File.open(filepath).each_line do |line|
    if line.start_with?('Time.Started.')
      status['Time_Started'] = line.split(': ')[-1].strip
    elsif line.start_with?('Time.Estimated.')
      status['Time_Estimated'] = line.split(': ')[-1].strip
    elsif line.start_with?('Recovered.')
      status['Recovered'] = line.split(': ')[-1].strip
    elsif line.start_with?('Input.Mode.')
      status['Input_Mode'] = line.split(': ')[-1].strip
    elsif line.start_with?('Speed.Dev.')
      item = line.split(': ')
      gpu = item[0].gsub!('Speed.Dev.', 'Speed Dev ').gsub!('.', '')
      status[gpu] = line.split(': ')[-1].strip
    elsif line.start_with?('HWMon.Dev.')
      item = line.split('.: ')
      gpu = item[0].gsub!('HWMon.Dev.', 'HWMon Dev ').gsub!('.', '')
      status[gpu] = line.split('.: ')[-1].strip
    end
  end
  return status
end

def hashcatDeviceParser(output)
  gpus = 0
  cpus = 0
  output.each_line do |line|
    if line.include?('Type')
      if line.split(': ')[-1].strip.include?('CPU')
        cpus += 1
      elsif line.split(': ')[-1].strip.include?('GPU')
        gpus += 1
      end
    end
  end
  puts "agent has #{cpus} CPUs"
  puts "agent has #{gpus} GPUs"
  return cpus, gpus
end

def hashcatBenchmarkParser(output)
  max_speed = ""
  output.each_line do |line|
    if line.start_with?('Speed.Dev.#')
      max_speed = line.split(': ')[-1].to_s
    end
  end
  puts "agent max cracking speed (single NTLM hash):\n #{max_speed}"
  return max_speed
end

def getHashcatPid
  pid = `ps -ef | grep hashcat | grep hc_cracked_ | grep -v 'ps -ef' | grep -v 'sh \-c' | awk '{print $2}'`
  return pid.chomp
end

# replace the placeholder binary path with the user defined path to hashcat binary
def replaceHashcatBinPath(cmd)
  cmd = cmd.gsub('@HASHCATBINPATH@', $hashcatbinpath)
  return cmd
end

# this function compares the agents local rules files to the master server's rules files
# if this agent is missing a rules file it will download them before taking jobs from queue.
def sync_rules_files()
  local_rulesfile_checksums = []

  server_rules = Api.rules()
  server_rules = JSON.parse(server_rules)
  if server_rules['type'] == 'Error'
    return false
  end

  # get our local list of rules
  localchecksums = Dir["control/rules/*.checksum"]
  unless localchecksums.empty?
    localchecksums.each do |checksumfile|
      # do nasty hack to get checksum from filename
      # TODO this should be filec ontents with rulesfilename.checksum as the file name
      checksum = checksumfile.split('/')[2].split('.checksum')[0]
      local_rulesfile_checksums << checksum
    end
  end

  server_rules['rules'].each do |server_rulesfile|
    # if our remote rules file checksum dont match our local rules file checksumchecksums, than download rulesfile by id
    unless local_rulesfile_checksums.include? server_rulesfile['checksum']
      puts "you need to download #{server_rulesfile['name']} = #{server_rulesfile['checksum']}"
      puts "Downloading..."
      local_rulesfile = Api.rule(server_rulesfile['id'])
      File.open(server_rulesfile['path'], 'w') do |f|
        f << local_rulesfile
      end

      # generate checksums for newly downloaded file
      checksum = Digest::SHA2.hexdigest(File.read(server_rulesfile['path']))
      File.open("control/rules/#{checksum}" + ".checksum", 'w') do |f|
        f.puts "#{checksum} #{server_rulesfile['path'].split("/")[-1]}"
      end
    end
  end
end


# this function compares the agents local wordlists to the master server's wordlists
# if this agent is missing wordlists it will download them before taking jobs from queue.
def sync_wordlists()
  localwordlists = []

  wordlists = Api.wordlists()
  wordlists = JSON.parse(wordlists)
  if wordlists['type'] == 'Error'
    return false
  end

  # get our local list of wordlists
  localchecksums = Dir["control/wordlists/*.checksum"]
  unless localchecksums.empty?
    localchecksums.each do |checksumfile|
      # do nasty hack to get checksum from filename
      checksum = checksumfile.split('/')[2].split('.checksum')[0]
      localwordlists << checksum
    end
  end

  wordlists['wordlists'].each do |wl|
    # if our remote wordlists dont match our local checksums, than download wordlist by id
    unless localwordlists.include? wl['checksum']
      puts "you need to download #{wl['name']} = #{wl['checksum']}"
      puts "Downloading..."
      File.open('control/tmp/' + wl['name'] + '.gz', 'w') {|f|
        block = proc { |response|
          response.read_body do |chunk|
            f.write chunk
          end
        }
        # Have to create our own request since response is not in json format
        options = JSON.parse(File.read('config/agent_config.json'))
        @server = options['master_ip'] + ":" + options['port']
        @uuid = options['uuid']
        url = "https://#{@server}/v1/wordlist/#{wl['id']}"
        RestClient::Request.new(
          method: :get, 
          url: url, 
          cookies: {:agent_uuid => @uuid},
          timeout: 43200,
          verify_ssl: false,
          block_response: block
          ).execute
      }
      cmd = "mv control/tmp/#{wl['name']}.gz control/wordlists/"
      `#{cmd}`
      puts "Unpacking...."
      cmd = "gunzip control/wordlists/#{wl['name']}.gz"
      `#{cmd}`

      # generate checksums for newly downloaded file
      puts "Calculating checksum"
      cmd = "control/wordlists/#{wl['name']}"
      checksum = `sha256sum "#{cmd}"`
     
      File.open("control/wordlists/#{checksum}" + ".checksum", 'w') do |f|
        f.puts "#{checksum.split(' ')[0]} #{wl['path'].split('/')[-1]}"
      end

    end
  end
end

# this function provides the master server with basic information about the agent
def hc_benchmark()
  cmd = $hashcatbinpath + ' -b -m 1000'
  hc_perfstats = `#{cmd}`
  return  hc_perfstats
end

def hc_device_list()
  cmd = $hashcatbinpath + ' -I'
  hc_devices = `#{cmd}`
  return  hc_devices
end

# is hashcat working? if so, how fast are you? provide basic information to master server
hc_cpus, hc_gpus = hashcatDeviceParser(hc_device_list)
hc_devices = {}
hc_devices['gpus'] = hc_gpus
hc_devices['cpus'] = hc_cpus
hc_perfstats = hashcatBenchmarkParser(hc_benchmark)

while(1)
  sleep(4)

  # find pid
  pid = getHashcatPid

  # wait a bit to avoid race condition
  if !pid.nil? and File.exist?('control/tmp/agent_current_task.txt')
    sleep(10)
    pid = getHashcatPid
  end

  # ok either do nothing or start working
  if pid.nil?
    puts "AGENT IS WORKING RIGHT NOW"
  else

    # if we have taskqueue tmp file locally, delete it
    File.delete('control/tmp/agent_current_task.txt') if File.exist?('control/tmp/agent_current_task.txt')

    # send heartbeat without hashcat status
    payload = {}
    payload['agent_status'] = 'Idle'
    payload['hc_benchmark'] = 'example data'
    payload['hc_status'] = ''
    heartbeat = Api.post_heartbeat(payload)
    puts '======================================'
    heartbeat = JSON.parse(heartbeat)
    puts heartbeat

    # upon initial authorization perfstats
    if heartbeat['type'] == 'message' and heartbeat['msg'] == 'Authorized'
      payload['agent_status'] = 'Syncing'
      sync_rules_files
      Api.stats(hc_devices, hc_perfstats)
    end

    if heartbeat['type'] == 'message' and heartbeat['msg'] == 'START'

      # Sync up before jobs starts
      payload['agent_status'] = 'Syncing'
      Api.post_heartbeat(payload)
      sync_wordlists

      jdata = Api.queue_by_id(heartbeat['task_id'])
      jdata = JSON.parse(jdata)

      # we must have an item from the queue before we start processing
      if jdata['type'] != 'Error'

        # save task data to tmp to signify we are working
        File.open('control/tmp/agent_current_task.txt', 'w') do |f|
          f.write(jdata)
        end

        # take queue item and set status to running
        Api.post_queue_status(jdata['id'], 'Running')

        # set the jobtask to running
        Api.post_jobtask_status(jdata['jobtask_id'], 'Running')

        # we need job details for hashfile id
        job = Api.job(jdata['job_id'])
        job = JSON.parse(job)

        # we need to get task_id which is stored in jobtasks
        jobtask = JSON.parse(Api.jobtask(jdata['jobtask_id']))

        # we dont need to download the wordlist b/c we are local agent, we already have them
        # wordlists Api.wordlists()
        # puts wordlists
        #puts Api.wordlist()

        # generate hashfile via api
        hashes = Api.hashfile(jobtask['id'], job['hashfile_id'])

        # write hashes to local filesystem
        hashfile = "control/hashes/hashfile_#{jdata['job_id']}_#{jobtask['task_id']}.txt"
        puts hashfile
        File.open(hashfile, 'w') do |f|
          f.puts hashes
        end

        # get our hashcat command and sub out the binary path
        cmd = jdata['command']
        cmd = replaceHashcatBinPath(cmd)
        puts cmd

        # this variable is used to determine if the job was canceled
        @canceled = false

        # # thread off hashcat
        run_time = 0
        thread1 = Thread.new {
          run_time = Benchmark.realtime do
            system(cmd)
          end
        }

        @jobid = jdata['job_id']
        # # continue to hearbeat while running job. look for a stop command
        catch :mainloop do
          while thread1.status do
            sleep 4
            puts "WORKING IN THREAD"
            puts "WORKING ON ID: #{jdata['id']}"
            payload = {}
            payload['agent_status'] = 'Working'
            payload['agent_task'] = jdata['id']
            # provide hashcat status with hearbeat
            payload['hc_status'] = hashcatParser("control/outfiles/hcoutput_#{@jobid}.txt")
            heartbeat = Api.post_heartbeat(payload)
            heartbeat = JSON.parse(heartbeat)

            if heartbeat['msg'] == 'Canceled'
              @canceled = true
              Thread.kill(thread1)
              # for some reason hashcat doesnt always get killed when terminating the thread.
              # manually kill it to be certain
              pid = getHashcatPid
              if pid
                `kill -9 #{pid}`
              end
              throw :mainloop
            end
          end
        end

        # set jobtask status to importing
        # commenting out now that we are chunking
        Api.post_queue_status(jdata['id'], 'Importing')

        # upload results
        crack_file = 'control/outfiles/hc_cracked_' + jdata['job_id'].to_s + '_' + jobtask['task_id'].to_s + '.txt'
        if File.exist?(crack_file)
          Api.upload_crackfile(jobtask['id'], crack_file, run_time)
        else
          puts "No successful cracks for this task. Skipping upload."
        end

        # remove task data tmp file
        File.delete('control/tmp/agent_current_task.txt') if File.exist?('control/tmp/agent_current_task.txt')

        # change status to completed for jobtask
        # commenting out now that we are chunking
        # if @canceled
        #   Api.post_jobtask_status(jdata['jobtask_id'], 'Canceled')
        # else
        #   Api.post_jobtask_status(jdata['jobtask_id'], 'Completed')
        # end

        # set taskqueue item to complete and remove from queue
        Api.post_queue_status(jdata['id'], 'Completed')
      end
    end
  end
end
