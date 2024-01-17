(* mirage >= 4.5.0 & < 4.6.0 *)
(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let setup = runtime_arg ~pos:__POS__ "Unikernel.K.setup"

let packages =
  [
    package ~min:"0.15.2" "x509";
    package "duration";
    package "logs";
    package ~min:"0.4.0" "letsencrypt" ;
    package ~min:"0.4.0" "letsencrypt-dns" ;
    package "dns-tsig";
    package ~min:"5.0.1" "dns-certify";
    package ~min:"5.0.0" ~sublibs:[ "mirage" ] "dns-server";
    package ~min:"6.4.0" "dns-client-mirage";
    package "randomconv";
    package ~min:"0.3.0" "domain-name";
    package ~min:"4.3.2" "mirage-runtime";
    package "letsencrypt-mirage";
]

let client =
  main ~runtime_args:[setup] ~packages ~pos:__POS__ "Unikernel.Client" @@
  random @-> pclock @-> mclock @-> time @-> stackv4v6 @-> alpn_client @-> job

let enable_monitoring =
  let doc = Key.Arg.info
      ~doc:"Enable monitoring (only available for solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let stack = generic_stackv4v6 default_network

let dns = generic_dns_client stack

let alpn_client =
  let dns =
    mimic_happy_eyeballs stack dns (generic_happy_eyeballs stack dns)
  in
  paf_client (tcpv4v6_of_stackv4v6 stack) dns

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management"))
    stack

let docs = "MONITORING PARAMETERS"

let name =
  runtime_arg ~pos:__POS__ ~name:"name"
    {|(let doc = Cmdliner.Arg.info ~doc:"Name of the unikernel" ~docs:%S [ "name" ] in
       Cmdliner.Arg.(value & opt string "a.ns.robur.coop" doc))|} docs

let monitoring =
  let monitor = Runtime_arg.(v (monitor ~docs None)) in
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
  let syslog = Runtime_arg.(v (syslog ~docs None)) in
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
