(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let dns_key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
  Key.(create "dns-key" Arg.(required string doc))

let dns_server =
  let doc = Key.Arg.info ~doc:"dns server IP" ["dns-server"] in
  Key.(create "dns-server" Arg.(required ip_address doc))

let port =
  let doc = Key.Arg.info ~doc:"dns server port" ["port"] in
  Key.(create "port" Arg.(opt int 53 doc))

let production =
  let doc = Key.Arg.info ~doc:"Use the production let's encrypt servers" ["production"] in
  Key.(create "production" Arg.(flag doc))

let account_key_seed =
  let doc = Key.Arg.info ~doc:"account key seed" ["account-key-seed"] in
  Key.(create "account-key-seed" Arg.(required string doc))

let account_key_type =
  let doc = Key.Arg.info ~doc:"account key type" ["account-key-type"] in
  Key.(create "account-key-type" Arg.(opt string "RSA" doc))

let account_bits =
  let doc = Key.Arg.info ~doc:"account public key bits" ["account-bits"] in
  Key.(create "account-bits" Arg.(opt int 4096 doc))

let email =
  let doc = Key.Arg.info ~doc:"Contact eMail address for let's encrypt" ["email"] in
  Key.(create "email" Arg.(opt (some string) None doc))

let monitor =
  let doc = Key.Arg.info ~doc:"monitor host IP" ["monitor"] in
  Key.(create "monitor" Arg.(opt (some ip_address) None doc))

let syslog =
  let doc = Key.Arg.info ~doc:"syslog host IP" ["syslog"] in
  Key.(create "syslog" Arg.(opt (some ip_address) None doc))

let name =
  let doc = Key.Arg.info ~doc:"Name of the unikernel" ["name"] in
  Key.(create "name" Arg.(opt string "sn.nqsb.io" doc))

let keys = [
  Key.v dns_key ; Key.v dns_server ; Key.v port ;
  Key.v production ;
  Key.v account_key_seed ; Key.v account_key_type ;
  Key.v account_bits ; Key.v email ;
  Key.v name ; Key.v syslog ; Key.v monitor ;
]

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
    package ~min:"6.4.0" ~sublibs:[ "mirage" ] "dns-client";
    package "randomconv";
    package ~min:"0.3.0" "domain-name";
    package ~min:"4.3.2" "mirage-runtime";
    package ~min:"0.4.0" "paf-le";
    package ~sublibs:["mirage"] ~min:"0.3.0" "logs-syslog";
    package "mirage-monitoring";
]

let management_stack = generic_stackv4v6 ~group:"management" (netif ~group:"management" "management")

let client =
  foreign ~keys ~packages "Unikernel.Client" @@
  console @-> random @-> pclock @-> mclock @-> time @-> stackv4v6 @-> stackv4v6 @-> job

let () =
  let net = generic_stackv4v6 default_network in
  register "letsencrypt"
    [ client $ default_console $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net $ management_stack ]
