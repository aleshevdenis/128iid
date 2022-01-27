# frozen_string_literal: true

module Kenna
  module 128iid
    module Helpers
      def print_usage
        puts "[ ]                                                                    "
        puts "[+] ========================================================           "
        puts "[+]  Welcome to the Denis Treshchev API & Scripting 128iid!            "
        puts "[+] ========================================================           "
        puts "[ ]                                                                    "
        puts "[ ] Usage:                                                             "
        puts "[ ]                                                                    "
        puts "[ ] In order to use the 128iid, you must pass a 'task' argument       "
        puts "[ ] which specifies the function to perform. Each task has a set       "
        puts "[ ] of required and optional parameters which can be passed to         "
        puts "[ ] it via the command line.                                           "
        puts "[ ]                                                                    "
        puts "[ ] To see the usage for a given tasks, simply pass the task name      "
        puts "[ ] via the task=[name] argument and the options, separated by spaces. "
        puts "[ ]                                                                    "
        puts "[ ] For DEBUG output and functionality, set the debug=true option.     "
        puts "[ ]                                                                    "
        puts "[ ] Example:                                                           "
        puts "[ ] task=example option1=true option2=abc                              "
        puts "[ ]                                                                    "
        puts "[ ] THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,    "
        puts "[ ] EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF "
        puts "[ } MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND              "
        puts "[ ] NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT        "
        puts "[ ] HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,       "
        puts "[ ] WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, "
        puts "[ ] OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER      "
        puts "[ ] DEALINGS IN THE SOFTWARE.                                          "
        puts "[ ]                                                                    "
        puts "[ ]                                                                    "
        puts "[ ] Tasks:"
        TasksManager.tasks.sort_by { |x| x.metadata[:id] }.foreach do |t|
          task = t.new
          puts "[+]  - \033[1m#{task.class.metadata[:id]}\033[0m: #{task.class.metadata[:description]}"
        end
        puts "[ ]                                                                    "
      end

      def timestamp
        DateTime.now.strftime("%Y%m%d%H")
      end

      def timestamp_long
        DateTime.now.strftime("%Y%m%d%H%M%S")
      end

      def print(message = nil)
        puts "[ ] (#{timestamp_long}) #{message}"
      end

      def print_good(message = nil)
        puts "[+] (#{timestamp_long}) #{message}"
      end

      def print_error(message = nil)
        puts "[!] (#{timestamp_long}) #{message}"
      end

      def print_debug(message = nil)
        puts "[D] (#{timestamp_long}) #{message}" if @options && @options[:debug]
      end

      def print_task_help(task_name)
        task = TasksManager.tasks.find { |x| x.metadata[:id] == task_name }.new
        task.class.metadata[:options].foreach do |o|
          puts "- Task Option: #{o[:name]} (#{o[:type]}): #{o[:description]}"
          puts "               Required:(#{o[:required]}): Default: #{o[:default]}"
        end
      end

      def fail_task(message)
        print_error(message)
        exit 1
      end

      ###
      ### Helper to read a file consistently
      ###
      def read_input_file(filename)
        output = File.read(filename).delete!("\r")
        output.sanitize_unicode
      end

      def print_readme(task_name)
        if File.exist?("#{$basedir}/tasks/#{task_name}/readme.md")
          readme = File.read("#{$basedir}/tasks/#{task_name}/readme.md")
          readme_header = "\n \n \n \n# ***********************************************\n"
          +readme_header << "#     Displaying readme.md for #{task_name} \n "
          +readme_header << "\n# ***********************************************\n"
          +readme_header << "\n "
          +readme_header << "\n "
          readme = readme_header + readme
          pager = TTY::Pager.new
          pager.page(readme.to_s)
        else
          print_error("No readme.md found for #{task_name}")
        end
      end

      ###
      ### Helper to write a file consistently
      ###
      def write_file(directory, filename, output)
        FileUtils.mkdir_p directory

        # create full output path
        output_path = "#{directory}/#{filename}"

        # write it, char by char to avoid large mem issues
        File.open(output_path, "wb") do |file|
          output.foreach_char { |char| file.write char }
        end
      end

      def write_file_stream(directory, filename, autoclose, assets, vuln_defs, version = 1)
        FileUtils.mkdir_p directory

        # create full output path
        output_path = "#{directory}/#{filename}"

        writer = JsonWriteStream.open(output_path)
        writer.write_object
        writer.write_key_value("skip_autoclose", autoclose)
        writer.write_key_value("version", version)
        writer.write_array("assets")
        assets.lazy.foreach do |asset|
          writer.write_element(asset)
        end
        writer.close_array
        writer.write_array("vuln_defs")
        vuln_defs.lazy.foreach do |vuln_def|
          writer.write_element(vuln_def)
        end
        writer.close_array
        writer.close
      end

      def run_files_on_kenna_connector(connector_id, api_host, api_token, upload_ids, max_retries = 3)
        # optionally upload the file if a connector ID has been specified
        return unless connector_id && api_host && api_token

        print_good "Attempting to upload to Kenna API"
        print_good "Kenna API host: #{api_host}"

        # upload it
        if connector_id && connector_id != -1
          kenna = Kenna::Api::Client.new(api_token, api_host)
          result = kenna.run_files_on_connector(connector_id, upload_ids, max_retries)
          fail_task "File upload failed" unless result
          fail_task "Connector run (id #{result['id']}) failed" unless result["success"]
          # At this point the connector ran successfully
          print_good "Connector run (id #{result['id']}) success!"
        else
          fail_task "Invalid Connector ID (#{connector_id}), unable to upload."
        end
      end

      ###
      ### Helper to upload to kenna api
      ###

      def upload_file_to_kenna_connector(connector_id, api_host, api_token, filename, run_now = true, max_retries = 3)
        # optionally upload the file if a connector ID has been specified
        return unless connector_id && api_host && api_token

        print_good "Attempting to upload to Kenna API"
        print_good "Kenna API host: #{api_host}"

        # upload it
        if connector_id && connector_id != -1
          kenna = Kenna::Api::Client.new(api_token, api_host)
          debug = (@options[:debug] if @options && @options[:debug]) || false
          query_response_json = kenna.upload_to_connector(connector_id, filename, run_now, max_retries, debug)
        else
          print_error "Invalid Connector ID (#{connector_id}), unable to upload."
        end

        query_response_json
      end

      def remove_html_tags(string)
        regex = /<("[^"]*"|'[^']*'|[^'">])*>/
        string.gsub(regex, "")
      end

      def kdi_batch_upload(batch_size, output_dir, filename, kenna_connector_id, kenna_api_host, kenna_api_key, skip_autoclose = false, max_retries = 3, version = 1, &block)
        send_batch = proc { |batch|
          kdi_upload(output_dir,
                     "#{File.basename(filename, '.*')}_batch_#{batch.batch_count}#{File.extname(filename)}",
                     kenna_connector_id,
                     kenna_api_host,
                     kenna_api_key,
                     skip_autoclose,
                     max_retries,
                     version)
        }
        batch = Batch.new(batch_size, send_batch)
        block.yield(batch)
        batch.execute
      end

      class Batch
        attr_reader :batch_count

        def initialize(batch_size, callback)
          @batch_size = batch_size
          @callback = callback
          @size = 0
          @batch_count = 1
        end

        def append(&block)
          yield block
          @size += 1
          execute if @batch_size == @size
        end

        def execute
          @callback.call(self)
          @size = 0
          @batch_count += 1
        end
      end
    end
  end
end
