# !!! THIS PROJECT IS DEPRICATED !!!
It will no longer be maintained. If you wish to use the latest version of hashview, please checkout https://github.com/hashview/hashview


# Hashview Agent

This is the headless agent that connects to the master instance of Hashview to support distributed cracking.

**Warning!** distributed support is very ALPHA. This agent only works with dev instances of Hashview!

More information about distributed support can be found here: [Hashview Wiki - Distributed Cracking](https://github.com/hashview/hashview/wiki/04_Distributed_Cracking)

## Prerequisites 

We strongly suggest using RVM: `\curl -sSL https://get.rvm.io | bash -s stable --ruby`

### Networking Requirements

Agents heartbeat to the master server where your full install of Hashview is located. You'll need inbound port 4567/tcp traffic for agents to communicate.

## Install

1. Clone the hashview-agent repo  

    `git clone https://github.com/hashview/hashview-agent` 
    
2. Install gems

     `gem install bundler`  
     `bundle install`

3. Provision the agent  

    `RACK_ENV=production rake provision_remote_agent`

    A new configuration file will be generated at `config/agent_config.json`. Note the UUID for the agent is generated at this time. This UUID should be treated similar to an API key.
4. Define your master server by IP (where the full install of Hashview is located) and path to your hashcat binary. Example config below:
```
{
  "master_ip": "192.168.1.1",
  "port": "4567",
  "uuid": "31c4ec48-e7b1-1af9-b1b0-7e1d77c57928",
  "hc_binary_path": "/home/meatball/hashcat-3.30/hashcat64.bin"
}
```
5. Start the agent 

    `RACK_ENV=production ruby agent.rb`
    
6. Verify you see the hearbeats on your master instance under the "Agents" menu. A status of 'Pending' will exist until you've authorized the agent to join the cluster. Once Authorized, the agent will take tasks off the queue and hearbeat with its hashcat status.

#### Happy Cracking!
