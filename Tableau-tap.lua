-- Tap to export capture to a suitable file for Tableau to read
-- File is just a CSV of interesting packets in an appropriate format, to suit a prepared Tableau workbook
-- Strings are double-quoted. Data lines have a trailing comma, because I'm lazy,
--
-- Chris Gadd
-- gaddman@email.com
-- v0.5-20150613
--
-- Known limitiations:
-- Not sure what will happen if you try this on a live capture.

if (gui_enabled()) then 
	-- Note that everything is "local" to this "if then" 
	-- this way we don't add globals (also means you can't use this tap from command line, but that's fine for now)

	local outfile -- output filehandle
	local default_filename = "tabshark.csv" -- in current directory
	-- declare the fields to be read. If you want to add more, just add them here and you're done.
	local ws_fieldlist = {	"frame.number","frame.time","frame.time_epoch","ip.src","ip.dst","tcp.srcport","tcp.dstport","tcp.len","tcp.ack",
							"tcp.seq","tcp.window_size","tcp.stream","tcp.flags.res","tcp.flags.ns","tcp.flags.cwr","tcp.flags.ecn","tcp.flags.urg",
							"tcp.flags.ack","tcp.flags.push","tcp.flags.reset","tcp.flags.syn","tcp.flags.fin","tcp.analysis.ack_lost_segment",
							"tcp.analysis.ack_rtt","tcp.analysis.acks_frame","tcp.analysis.bytes_in_flight","tcp.analysis.duplicate_ack",
							"tcp.analysis.duplicate_ack_frame","tcp.analysis.duplicate_ack_num","tcp.analysis.fast_retransmission",
							"tcp.analysis.flags","tcp.analysis.initial_rtt","tcp.analysis.keep_alive","tcp.analysis.keep_alive_ack",
							"tcp.analysis.lost_segment","tcp.analysis.out_of_order","tcp.analysis.retransmission","tcp.analysis.reused_ports",
							"tcp.analysis.rto","tcp.analysis.rto_frame","tcp.analysis.spurious_retransmission","tcp.analysis.window_full",
							"tcp.analysis.window_update","tcp.analysis.zero_window","tcp.analysis.zero_window_probe",
							"tcp.analysis.zero_window_probe_ack","_ws.expert.message"}
	local ws_fields = {}
	for fieldnum = 1, #ws_fieldlist do
		ws_fields[fieldnum] = Field.new(ws_fieldlist[fieldnum])
	end
	
	local function export_packets()
		-- create tap
		local tap = Listener.new("frame", "tcp") -- filter on tcp
		-- this function will be called for every packet which matches the Listener filter
		function tap.packet(pinfo,tvb,tapdata)
			-- read all the fields we want into local variables and sanitize
			local output_fields = {}
			for fieldnum = 1, #ws_fieldlist do
				output_fields[fieldnum] = ws_fields[fieldnum]()

				if output_fields[fieldnum] then
					-- field exists, get value and sanitize it
					-- we use .label rather than .value, so that frame.time field is coerced into a string rather than an integer (epoch)
					--  and boolean types return 1/0 rather than true/false
					output_fields[fieldnum] = output_fields[fieldnum].label
					if output_fields[fieldnum] == "(none)" then
						-- probably the tcp.analysis fields, which either don't exist if not applicable, or have a value of nil/(none) if they do. Convert to 1
						-- note that these fields return "nil" if tostring(field.value) but "(none)" if tostring(field) or field.label
						output_fields[fieldnum] = 1
					elseif tonumber(output_fields[fieldnum]) == nil then
						-- must be a string field, quote it
						-- note, will also quote IP addresses
						output_fields[fieldnum] = '"'..output_fields[fieldnum]..'"'
					end
				else
					-- field doesn't exist in this packet or has nil value
					output_fields[fieldnum] = ""
				end
			end -- for fieldnum loop
			
			-- now write this packet to file
			thisline = ""
			for fieldnum = 1, #output_fields do
				thisline = thisline..output_fields[fieldnum]..","
			end
			outfile:write(thisline.."\n")
			outfile:flush()
		end --tap.packet function

		-- this is where things actually start happening for an existing capture.
		-- Not sure what will happen if you run a live capture with this function, but I assume it will be bad
		retap_packets()
		tap:remove()
	end -- export packets function

	local function export_capture(outfilename)
		if outfilename == "" then outfilename = default_filename end
		outfile = assert(io.open(outfilename, "w+b"))
		-- output the header line
		local thisline = table.concat(ws_fieldlist,",").."\n"
		outfile:write(thisline)
		outfile:flush()
		export_packets()
		outfile:close()
	end

	-- menu functions
	local function Tableau_export()
		local current_dir=io.popen"cd":read'*l'
		local filename = "Enter filename or leave blank for default (" .. current_dir .. "\\" .. default_filename .. ")"
		local response = new_dialog("Wireshark Tableau-tap: Export to Tableau",export_capture,filename)
	end
	local function Tableau_server()
		browser_open_url("http://qptbwp01f/#/projects")
	end
	local function Tableau_help()
		browser_open_url("https://youtu.be/0k8_7rgMD2c?t=680")
	end

	-- register the menu
	register_menu("Tableau/Export TCP packets to file",Tableau_export,MENU_TOOLS_UNSORTED)
	register_menu("Tableau/Projects", Tableau_server, MENU_TOOLS_UNSORTED)
	register_menu("Tableau/Help", Tableau_help, MENU_TOOLS_UNSORTED)

end --gui enabled
