(* mirage >= 4.8.0 & < 4.9.0 *)
(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let packages =
  [
    package ~min:"0.15.2" "x509";
    package "duration";
    package "logs";
    package ~min:"0.4.0" "letsencrypt" ;
    package ~min:"0.4.0" "letsencrypt-dns" ;
    package "dns-tsig";
    package ~min:"9.1.0" "dns-certify";
    package ~min:"9.1.0" ~sublibs:[ "mirage" ] "dns-server";
    package ~min:"9.1.0" "dns-client-mirage";
    package "randomconv";
    package ~min:"0.3.0" "domain-name";
    package ~min:"4.3.2" "mirage-runtime";
    package "letsencrypt-mirage";
]

let client =
  main ~packages ~pos:__POS__ "Unikernel.Client" @@
  random @-> pclock @-> mclock @-> time @-> stackv4v6 @-> alpn_client @-> job

let enable_monitoring =
  let doc = Key.Arg.info
      ~doc:"Enable monitoring (syslog, metrics to influx, log level, statmemprof tracing)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let stack = generic_stackv4v6 default_network

let alpn_client =
  let happy_eyeballs = generic_happy_eyeballs stack in
  let dns = generic_dns_client stack happy_eyeballs in
  let mimic = mimic_happy_eyeballs stack happy_eyeballs dns in
  paf_client (tcpv4v6_of_stackv4v6 stack) mimic

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management"))
    stack

let name =
  runtime_arg ~pos:__POS__
    {|let doc = Cmdliner.Arg.info ~doc:"Name of the unikernel"
        ~docs:Mirage_runtime.s_log [ "name" ]
      in
      Cmdliner.Arg.(value & opt string "a.ns.robur.coop" doc)|}

let monitoring =
  let monitor = Runtime_arg.(v (monitor None)) in
  let connect _ modname = function
    | [ _ ; _ ; stack ; name ; monitor ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
         | Some ip -> %s.create ip ~hostname:%s %s)"
        monitor modname name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_args:[ name ; monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_arg.(v (syslog None)) in
  let connect _ modname = function
    | [ _ ; stack ; name ; syslog ] ->
      code ~pos:__POS__
        "Lwt.return (match %s with\
         | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
         | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%s ()))"
        syslog modname stack name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_args:[ name ; syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    noop

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ pclock $ stack)
    noop

let () =
  register "letsencrypt"
    [
      optional_syslog default_posix_clock management_stack ;
      optional_monitoring default_time default_posix_clock management_stack ;
      client $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ stack $ alpn_client
    ]
