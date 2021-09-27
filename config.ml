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

let keys = Key.[
    abstract dns_key ; abstract dns_server ; abstract port ;
    abstract production ;
    abstract account_key_seed ; abstract account_key_type ;
    abstract account_bits ; abstract email
  ]

let packages =
  [
    package ~min:"0.13.0" "x509";
    package "duration";
    package "logs";
    package ~min:"4.0.0" "cohttp-mirage";
    package ~min:"0.4.0" "letsencrypt" ;
    package ~min:"0.4.0" "letsencrypt-dns" ;
    package ~min:"4.0.0" "conduit-mirage";
    package "dns-tsig";
    package ~min:"5.0.1" "dns-certify";
    package ~min:"5.0.0" ~sublibs:[ "mirage" ] "dns-server";
    package "randomconv";
    package ~min:"0.3.0" "domain-name";
    package ~min:"3.10.4" "mirage-runtime";
]

let client =
  foreign ~keys ~packages "Unikernel.Client" @@
  random @-> pclock @-> mclock @-> time @-> stackv4v6 @-> http_client @-> job

let () =
  let net = generic_stackv4v6 default_network in
  let res_dns = resolver_dns net in
  let conduit = conduit_direct ~tls:true net in
  register "letsencrypt"
    [ client $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net $ cohttp_client res_dns conduit ]
