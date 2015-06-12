#!/usr/bin/env ruby

require 'pp'
require 'graphviz'
module ThreatSpec
  
  FUNCTION_PATTERN = /^\s*(?:\/\/|\#)\s*ThreatSpec (?<model>.+?) for (?<function>.+?)\s*$/
  MITIGATION_PATTERN = /^\s*(?:\/\/|\#)\s*Mitigates (?<component>.+?) against (?<threat>.+?) with (?<mitigation>.+?)\s*(?:\((?<ref>.*?)\))?\s*$/
  EXPOSURE_PATTERN = /^\s*(?:\/\/|\#)\s*Exposes (?<component>.+?) to (?<threat>.+?) with (?<exposure>.+?)\s*(?:\((?<ref>.*?)\))?\s*$/
  DOES_PATTERN = /^\s*(?:\/\/|\#)\s*Does (?<action>.+?) for (?<component>.+?)\s*(?:\((?<ref>.*?)\))?\s*$/
  TEST_PATTERN = /^\s*(?:\/\/|\#)\s*Tests (?<function>.+?) for (?<threat>.+?)\s*(?:\((?<ref>.*?)\))?\s*$/
  GO_FUNC_PATTERN = /^\s*func\s+(?<code>(?<function>.+?)\(.*?)\s*{$/
  GRAPH_PATTERN = /^(?<caller>.+?)\t--(?<dynamic>.+?)-(?<line>\d+):(?<column>\d+)-->\t(?<callee>.+?)$/ 
  ZONE_PATTERN = /^(?<zone>.+?):(?<component>.+?)$/
  SENDRECEIVE_PATTERN = /^\s*(?:\/\/|\#)\s*(?<direction>Sends|Receives) (?<subject>.+?) from (?<from_component>.+?) to (?<to_component>.+?)$/

  def self.parse_component(component)
    if match = ZONE_PATTERN.match(component)
      return [match[:component], match[:zone]]
    else
      return [component, component]
    end
  end
    
  class Function
    attr_accessor :model, :function, :mitigations, :exposures, :does, :sendreceives, :tests, :raw, :code, :file, :line_number
    def initialize(model, function, raw)
      @model = model
      @function = function
      @mitigations = []
      @exposures = []
      @does = []
      @sendreceives = []
      @tests = []
      @raw = raw
    end
  end

  class Mitigation
    attr_accessor :threat, :mitigation, :ref, :raw, :component, :zone
    def initialize(component, threat, mitigation, ref, raw)
      (@component, @zone) = ThreatSpec.parse_component(component)
      @threat = threat
      @mitigation = mitigation
      @ref = ref
      @raw = raw
    end
  end

  class Exposure
    attr_accessor :threat, :exposure, :ref, :raw, :component, :zone
    def initialize(component, threat, exposure, ref, raw)
      (@component, @zone) = ThreatSpec.parse_component(component)
      @threat = threat
      @exposure = exposure
      @ref = ref
      @raw = raw
    end
  end

  class Does
    attr_accessor :action, :ref, :raw, :component, :zone
    def initialize(action, component, ref, raw)
      (@component, @zone) = ThreatSpec.parse_component(component)
      @action = action
      @ref = ref
      @raw = raw
    end
  end

  class SendReceive
    attr_accessor :direction, :subject, :from_component, :to_component, :from_zone, :to_zone
    def initialize(direction, subject, from_component, to_component, raw)
      (@from_component, @from_zone) = ThreatSpec.parse_component(from_component)
      (@to_component, @to_zone) = ThreatSpec.parse_component(to_component)
      @direction = direction.downcase
      @subject = subject
      @raw = raw
    end
  end

  class Test
    attr_accessor :function, :threat, :ref, :raw
    def initialize(function, threat, ref, raw)
      @function = function
      @threat = threat
      @ref = ref
      @raw = raw
    end
  end

  class Parser
    attr_accessor :current_function, :models

    def initialize
      @functions = {}
      @functions_found = {}
      @functions_covered = {}
      @functions_tested = {}
    end

    def parse_function(match, line)
      @current_function = Function.new(match[:model], match[:function], line)
    end

    def parse_mitigation(match, line)
      if @current_function
        @functions_covered[@current_function] ||= 0
        @functions_covered[@current_function] += 1
        mitigation = Mitigation.new(match[:component], match[:threat], match[:mitigation], match[:ref], line)
        @current_function.mitigations << mitigation
      else
        puts "Orphaned: #{line}"
      end
    end

    def parse_exposure(match, line)
      if @current_function
        @functions_covered[@current_function] ||= 0
        @functions_covered[@current_function] += 1
        exposure = Exposure.new(match[:component], match[:threat], match[:exposure], match[:ref], line)
        @current_function.exposures << exposure
      else
        puts "Orphansed: #{line}"
      end
    end

    def parse_does(match, line)
      if @current_function
        @functions_covered[@current_function] ||= 0
        @functions_covered[@current_function] += 1
        does = Does.new(match[:action], match[:component], match[:ref], line)
        @current_function.does << does
      else
        puts "Orphansed: #{line}"
      end
    end

    def parse_sendreceive(match, line)
      if @current_function
        @functions_covered[@current_function] ||= 0
        @functions_covered[@current_function] += 1
        sendreceive = SendReceive.new(match[:direction], match[:subject], match[:from_component], match[:to_component], line)
        @current_function.sendreceives << sendreceive
      else
        puts "Orphansed: #{line}"
      end
    end

    def parse_test(match, line)
      if @current_function
        @functions_tested[match[:function]] ||= 0
        @functions_tested[match[:function]] += 1
        test = Test.new(match[:function], match[:threat], match[:ref], line)
        @current_function.tests << test
      else
        puts "Orphaned: #{line}"
      end
    end

    def parse_go_function(match, line)
      @functions_found[match[:function]] ||= 0
      @functions_found[match[:function]] += 1
      if @current_function && match[:function].split(' ').last == @current_function.function.split('.').last
        @current_function.code = match[:code]
        @current_function.file = @file
        @current_function.line_number = @line_number
      end
    end

    def parse(file, code)
      @file = file
      @line_number = 1
      code.each_line do |line|
        line.chomp!
        if match = FUNCTION_PATTERN.match(line)
          parse_function(match, line)
        elsif match = MITIGATION_PATTERN.match(line)
          parse_mitigation(match, line)
        elsif match = EXPOSURE_PATTERN.match(line)
          parse_exposure(match, line)
        elsif match = DOES_PATTERN.match(line)
          parse_does(match, line)
        elsif match = SENDRECEIVE_PATTERN.match(line)
          parse_sendreceive(match, line)
        elsif match = TEST_PATTERN.match(line)
          parse_test(match, line)
        elsif match = GO_FUNC_PATTERN.match(line)
          parse_go_function(match, line)
        end
        @line_number += 1
        if @current_function
          @functions[@current_function.function] = @current_function
        end
      end
    end

    def to_key(x)
      x.downcase.gsub(/[^a-z0-9]/, '')
    end

    def component_key(zone, component) 
      to_key(zone) + "-" + to_key(component)
    end

    def analyze
      @components = {}
      @functions.each_pair do |function_name, function|
        function.mitigations.each do |mitigation|
          ckey = component_key(mitigation.zone, mitigation.component)
          @components[ckey] ||= {:threats => {}, :actions => [], :zone => mitigation.zone, :component => mitigation.component}
          @components[ckey][:threats][mitigation.threat] ||= {:mitigations => [], :exposures => []}
          @components[ckey][:threats][mitigation.threat][:mitigations] << { :mitigation => mitigation, :file => function.file, :line => function.line_number, :function => function_name}
        end

        function.exposures.each do |exposure|
          ckey = component_key(exposure.zone, exposure.component)
          @components[ckey] ||= {:threats => {}, :actions => [], :zone => exposure.zone, :component => exposure.component}
          @components[ckey][:threats][exposure.threat] ||= {:mitigations => [], :exposures => []}
          @components[ckey][:threats][exposure.threat][:exposures] <<  { :exposure => exposure, :file => function.file, :line => function.line_number, :function => function_name}
        end

        function.does.each do |does|
          ckey = component_key(does.zone, does.component)
          @components[ckey] ||= {:threats => {}, :actions => [], :zone => does.zone, :component => does.component}
          @components[ckey][:actions] << does.action
        end
      end
    end

    def summary
      pp @functions
    end

    def report
      num_found = @functions_found.size
      num_covered = @functions_covered.size
      num_tested = @functions_tested.size

      puts "# ThreatSpec Report for ..."
      puts ""
      puts "# Analysis"
        puts "* Functions found: #{num_found}"
        puts "* Functions covered: #{(100*num_covered.to_f/num_found.to_f).round(2)}% (#{num_covered})"
        puts "* Functions tested: #{(100*num_tested.to_f/num_covered.to_f).round(2)}% (#{num_tested})"
      puts ""
      puts "# Components"
      @components.each_pair do |ckey, component|
        puts "## #{component[:zone]} #{component[:component]}"
        component[:threats].each_pair do |threat_name, threat|
          puts "### Threat: #{threat_name}"
          threat[:mitigations].each do |mitigation|
            file = mitigation[:file]
            line = mitigation[:line]
            function = mitigation[:function]
            puts "* Mitigation: #{mitigation[:mitigation].mitigation} (#{function} in #{file}:#{line})"
          end
          threat[:exposures].each do |exposure|
            file = exposure[:file]
            line = exposure[:line]
            function = exposure[:function]
            puts "* Exposure: #{exposure[:exposure].exposure} (#{function} in #{file}:#{line})"
          end
          puts ""
        end
      end
    end

    def parse_graph
      @call_graph = {}
      #return unless STDIN.tty?

      contents = STDIN.read

      return unless contents.size > 0

      contents.each_line do |line|
        if match = GRAPH_PATTERN.match(line)
          caller_name = match[:caller].gsub(/(\$\d+)+/,'')
          callee_name = match[:callee].gsub(/(\$\d+)+/,'')
          @call_graph[caller_name] ||= {}
          @call_graph[caller_name][callee_name] ||= []
          @call_graph[caller_name][callee_name] << { :line => match[:line], :column => match[:column] }
        end
      end
    end

    def graph

      parse_graph

      threat_graph = {}
      mitigations = {}
      exposures = {}
      sendreceives = []

      @functions.each_pair do |caller_name, caller_function|
        caller_function.sendreceives.each do |sr|
          sendreceives << sr
        end

        if graph_caller = @call_graph[caller_name]
          source_components = []

          @functions[caller_name].mitigations.each do |x|
            ckey = component_key(x.zone, x.component)
            source_components << ckey
            mitigations[ckey] ||= 0
            mitigations[ckey] += 1
          end
          @functions[caller_name].exposures.each do |x|
            ckey = component_key(x.zone, x.component)
            source_components << ckey
            exposures[ckey] ||= 0
            exposures[ckey] += 1
          end
          @functions[caller_name].does.each do |x|
            ckey = component_key(x.zone, x.component)
            source_components << ckey
          end

          source_components.uniq!

          graph_caller.each_pair do |callee_name, graph|
            if @functions.has_key?(callee_name)
              dest_components = []
              mitigations_count = 0
              exposures_count = 0

              @functions[callee_name].mitigations.each do |x|
                ckey = component_key(x.zone, x.component)
                dest_components << ckey
                mitigations[ckey] ||= 0
                mitigations[ckey] += 1
              end
              @functions[callee_name].exposures.each do |x|
                ckey = component_key(x.zone, x.component)
                dest_components << ckey
                exposures[ckey] ||= 0
                exposures[ckey] += 1
              end
              @functions[callee_name].does.each do |x|
                ckey = component_key(x.zone, x.component)
                dest_components << ckey
              end
              dest_components.uniq!

              source_components.each do |s|
                dest_components.each do |d|
                  threat_graph[s] ||= {}
                  threat_graph[s][d] ||= []
                  threat_graph[s][d] << {:callee => callee_name, :mitigations => @functions[callee_name].mitigations.size, :exposures => @functions[callee_name].exposures.size}
                end
              end
            end
          end
        end
      end

      g = GraphViz.new( :G, :type => :digraph, :rankdir => 'LR', :overlap => 'scalexy', :nodesep => 0.6)
      g["compound"] = "true"
      g.edge["lhead"] = ""
      g.edge["ltail"] = ""

      nodes = {}
      zones = {}

      threat_graph.each_pair do |source, more|
        source_component = @components[source]
        zone = source_component[:zone]

        zone_key = to_key(zone)
        unless zones.has_key?(zone_key)
          zones[zone_key] = g.add_graph("cluster_#{zone_key}")
          zones[zone_key][:label] = zone
          zones[zone_key][:style] = 'dashed'
        end

        unless nodes.has_key?(source)
          nodes[source] = zones[zone_key].add_nodes(source)
          nodes[source][:label] = source_component[:component]

          if exposures.has_key?(source) and exposures[source] > 0
            if mitigations.has_key?(source) and mitigations[source] > 0
              nodes[source][:color] = 'orange'
            else
              nodes[source][:color] = 'red'
            end
          else
            if mitigations.has_key?(source) and mitigations[source] > 0
              nodes[source][:color] = 'darkgreen'
            end
          end
          nodes[source][:shape] = 'box'
        end

        more.each_pair do |dest, funcs|
          dest_component = @components[dest]
          zone = dest_component[:zone]

          zone_key = to_key(zone)
          unless zones.has_key?(zone_key)
            zones[zone_key] = g.add_graph("cluster_#{zone_key}")
            zones[zone_key][:label] = zone
            zones[zone_key][:style] = 'dashed'
          end

          unless nodes.has_key?(dest)
            nodes[dest] = zones[zone_key].add_nodes(dest)
            nodes[dest][:label] = dest_component[:component]
            if exposures.has_key?(dest) and exposures[dest] > 0
              if mitigations.has_key?(dest) and mitigations[dest] > 0
                nodes[dest][:color] = 'orange'
              else
                nodes[dest][:color] = 'red'
              end
            else
              if mitigations.has_key?(dest) and  mitigations[dest] > 0
                nodes[dest][:color] = 'darkgreen'
              end
            end
            nodes[dest][:shape] = 'box'
          end

          label = []
          label_color = 'black'
          funcs.each do |f|
            if f[:exposures] > 0
              if f[:mitigations] > 0
                color = "orange"
                label_color = "orange" unless label_color == "red"
              else
                color = "red"
                label_color = "red"
              end
            else
              if f[:mitigations] > 0
                color = "darkgreen"
                label_color = "darkgreen" if label_color == "black"
              else
                color = "black"
              end
            end
            label << "<font color=\"#{color}\">#{f[:callee]}</font>"
          end

          edge = g.add_edges(nodes[source], nodes[dest], :label => "<"+label.uniq.join("<br/>\n")+">", :color => label_color)
        end
      end

      sendreceives.each do |sr|
        zone_key = to_key(sr.from_zone)
        unless zones.has_key?(zone_key)
          zones[zone_key] = g.add_graph("cluster_#{zone_key}")
          zones[zone_key][:label] = sr.from_zone
          zones[zone_key][:style] = 'dashed'
        end
        from_node_key = component_key(sr.from_zone, sr.from_component)
        unless nodes.has_key?(from_node_key)
          nodes[from_node_key] = zones[zone_key].add_nodes(from_node_key)
          nodes[from_node_key][:label] = sr.from_component
          nodes[from_node_key][:shape] = 'oval'
        end

        zone_key = to_key(sr.to_zone)
        unless zones.has_key?(zone_key)
          zones[zone_key] = g.add_graph("cluster_#{zone_key}")
          zones[zone_key][:label] = sr.to_zone
          zones[zone_key][:style] = 'dashed'
        end

        to_node_key = component_key(sr.to_zone, sr.to_component)
        unless nodes.has_key?(to_node_key)
          nodes[to_node_key] = zones[zone_key].add_nodes(to_node_key)
          nodes[to_node_key][:label] = sr.to_component
          nodes[to_node_key][:shape] = 'oval'
        end

        if sr.direction == 'sends'
          color = 'blue'
        else
          color = 'purple'
        end

        label = ["<font color=\"#{color}\">#{sr.subject}</font>"]
        edge = g.add_edges(nodes[from_node_key], nodes[to_node_key], :label => "<"+label.uniq.join("<br/>\n")+">", :color => color)
      end
      g.output( :png => "threatspec.png" )
    end

  end

end

parser = ThreatSpec::Parser.new

ARGV.each do |file| 
  parser.parse file, File.open(file).read
end
parser.analyze
#parser.summary
parser.report
parser.graph
