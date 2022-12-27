(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Dns

let err_to_exit ~prefix = function
  | Ok x -> x
  | Error `Msg msg ->
    Logs.err (fun m -> m "error in %s: %s" prefix msg);
    exit Mirage_runtime.argument_error

(* borrowed from paf-le-chien/lib/lE.ml at 4961f8e9170200ec09efe167b749544e9fbe868d *)

module Httpaf_Client_connection = struct
  include Httpaf.Client_connection

  let yield_reader _ = assert false

  let next_read_operation t =
    (next_read_operation t :> [ `Close | `Read | `Yield ])
end

let with_uri uri ctx =
  let scheme = Mimic.make ~name:"paf-le-scheme"
  and port = Mimic.make ~name:"paf-le-port"
  and domain_name = Mimic.make ~name:"paf-le-domain-name"
  and ipaddr = Mimic.make ~name:"paf-le-ipaddr"
  in
  let scheme_v =
    match Uri.scheme uri with
    | Some "http" -> Some `HTTP
    | Some "https" -> Some `HTTPS
    | _ -> None in
  let port_v =
    match (Uri.port uri, scheme_v) with
    | Some port, _ -> Some port
    | None, Some `HTTP -> Some 80
    | None, Some `HTTPS -> Some 443
    | _ -> None in
  let domain_name_v, ipaddr_v =
    match Uri.host uri with
    | Some v -> (
        match
          ( Result.bind (Domain_name.of_string v) Domain_name.host,
            Ipaddr.of_string v )
        with
        | _, Ok v -> (None, Some v)
        | Ok v, _ -> (Some v, None)
        | _ -> (None, None))
    | _ -> (None, None) in
  let ctx =
    Option.fold ~none:ctx ~some:(fun v -> Mimic.add scheme v ctx) scheme_v in
  let ctx = Option.fold ~none:ctx ~some:(fun v -> Mimic.add port v ctx) port_v in
  let ctx =
    Option.fold ~none:ctx ~some:(fun v -> Mimic.add ipaddr v ctx) ipaddr_v in
  let ctx =
    Option.fold ~none:ctx
      ~some:(fun v -> Mimic.add domain_name v ctx)
      domain_name_v in
  ctx

let with_host headers uri =
  let hostname = Uri.host_with_default ~default:"localhost" uri in
  let hostname =
    match Uri.port uri with
    | Some port -> Fmt.str "%s:%d" hostname port
    | None -> hostname in
  Httpaf.Headers.add_unless_exists headers "host" hostname

let with_transfer_encoding ~chunked (meth : [ `GET | `HEAD | `POST ]) body
    headers =
  match (meth, chunked, body, Httpaf.Headers.get headers "content-length") with
  | `GET, _, _, _ -> headers
  | _, (None | Some false), _, Some _ -> headers
  | _, Some true, _, (Some _ | None) | _, None, `Stream _, None ->
      (* XXX(dinosaure): I'm not sure that the [Some _] was right. *)
      Httpaf.Headers.add_unless_exists headers "transfer-encoding" "chunked"
  | _, (None | Some false), `Empty, None ->
      Httpaf.Headers.add_unless_exists headers "content-length" "0"
  | _, (None | Some false), `String str, None ->
      Httpaf.Headers.add_unless_exists headers "content-length"
        (string_of_int (String.length str))
  | _, (None | Some false), `Strings sstr, None ->
      let len = List.fold_right (fun s acc -> acc + String.length s) sstr 0 in
      Httpaf.Headers.add_unless_exists headers "content-length"
        (string_of_int len)
  | _, Some false, `Stream _, None ->
      invalid_arg "Impossible to transfer a stream with a content-length value"

module HTTP : Letsencrypt__HTTP_client.S with type ctx = Mimic.ctx (* FIXME *) =
struct
  type ctx = Mimic.ctx

  module Headers = struct
    include Httpaf.Headers

    let init_with field value = of_list [ (field, value) ]
    let get_location hdrs = Option.map Uri.of_string (get hdrs "location")
  end

  module Body = struct
    type t =
      [ `Stream of string Lwt_stream.t
      | `Empty
      | `String of string
      | `Strings of string list ]

    let of_string str = `String str

    let to_string = function
      | `Stream t ->
          let open Lwt.Infix in
          Lwt_stream.to_list t >|= String.concat ""
      | `String str -> Lwt.return str
      | `Empty -> Lwt.return ""
      | `Strings sstr -> Lwt.return (String.concat "" sstr)
  end

  module Response = struct
    include Httpaf.Response

    let status resp = Httpaf.Status.to_code resp.Httpaf.Response.status
    let headers resp = resp.Httpaf.Response.headers
  end

  let error_handler mvar err = Lwt.async @@ fun () -> Lwt_mvar.put mvar err

  let response_handler mvar pusher resp body =
    let on_eof () = pusher None in
    let rec on_read buf ~off ~len =
      let str = Bigstringaf.substring buf ~off ~len in
      pusher (Some str) ;
      Httpaf.Body.schedule_read ~on_eof ~on_read body in
    Httpaf.Body.schedule_read ~on_eof ~on_read body ;
    Lwt.async @@ fun () -> Lwt_mvar.put mvar resp

  let rec unroll body stream =
    let open Lwt.Infix in
    Lwt_stream.get stream >>= function
    | Some str ->
        Httpaf.Body.write_string body str ;
        unroll body stream
    | None ->
        Httpaf.Body.close_writer body ;
        Lwt.return_unit

  let transmit cohttp_body httpaf_body =
    match cohttp_body with
    | `Empty -> Httpaf.Body.close_writer httpaf_body
    | `String str ->
        Httpaf.Body.write_string httpaf_body str ;
        Httpaf.Body.close_writer httpaf_body
    | `Strings sstr ->
        List.iter (Httpaf.Body.write_string httpaf_body) sstr ;
        Httpaf.Body.close_writer httpaf_body
    | `Stream stream -> Lwt.async @@ fun () -> unroll httpaf_body stream

  exception Invalid_response_body_length of Httpaf.Response.t
  exception Malformed_response of string

  let call ?(ctx = Mimic.empty) ?(headers = Httpaf.Headers.empty)
      ?(body = `Empty) ?chunked (meth : [ `GET | `HEAD | `POST ]) uri =
    let ctx = with_uri uri ctx in
    let headers = with_host headers uri in
    let headers = with_transfer_encoding ~chunked meth body headers in
    let req =
      Httpaf.Request.create ~headers
        (meth :> Httpaf.Method.t)
        (Uri.path_and_query uri) in
    let stream, pusher = Lwt_stream.create () in
    let mvar_res = Lwt_mvar.create_empty () in
    let mvar_err = Lwt_mvar.create_empty () in
    let open Lwt.Infix in
    Mimic.resolve ctx >>= function
    | Error (#Mimic.error as err) ->
        Lwt.fail (Failure (Fmt.str "%a" Mimic.pp_error err))
    | Ok flow -> (
        let error_handler = error_handler mvar_err in
        let response_handler = response_handler mvar_res pusher in
        let httpaf_body, conn =
          Httpaf.Client_connection.request ~error_handler ~response_handler req
        in
        Lwt.async (fun () ->
            Paf.run (module Httpaf_Client_connection) conn flow) ;
        transmit body httpaf_body ;
        Lwt.pick
          [
            (Lwt_mvar.take mvar_res >|= fun res -> `Response res);
            (Lwt_mvar.take mvar_err >|= fun err -> `Error err);
          ]
        >>= function
        | `Error (`Exn exn) -> Mimic.close flow >>= fun () -> Lwt.fail exn
        | `Error (`Invalid_response_body_length resp) ->
            Mimic.close flow >>= fun () ->
            Lwt.fail (Invalid_response_body_length resp)
        | `Error (`Malformed_response err) ->
            Mimic.close flow >>= fun () -> Lwt.fail (Malformed_response err)
        | `Response resp -> Lwt.return (resp, `Stream stream))

  open Lwt.Infix

  let head ?ctx ?headers uri = call ?ctx ?headers `HEAD uri >|= fst
  let get ?ctx ?headers uri = call ?ctx ?headers `GET uri

  let post ?ctx ?body ?chunked ?headers uri =
    call ?ctx ?body ?chunked ?headers `POST uri
end

(* end of borrowed code *)

module Client (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (T : Mirage_time.S) (S : Tcpip.Stack.V4V6) (_: sig end) = struct
  module Acme = Letsencrypt.Client.Make(HTTP)

  module D = Dns_mirage.Make(S)
  module DS = Dns_server_mirage.Make(P)(M)(T)(S)

  (* act as a hidden dns secondary and receive notifies, sweep through the zone for signing requests without corresponding (non-expired) certificate

     requires transfer and update keys

     on startup or when a notify is received, we fold over all TLSA records
      if there's a single csr and no valid and public-key matching cert get a cert from let's encrypt
      let's encrypt (http[s]) and dns challenge is used
      resulting certificate is nsupdated to primary dns

     Acme.initialise is done just at boottime

     then zone transfer and notifies is acted upon

     for each new tlsa record where selector = private and the content can be
       parsed as csr with a domain name we have keys for (or update uses the
       right key)
 *)

  let valid_and_matches_csr csr cert =
    (* parse csr, parse cert: match public keys, match validity of cert *)
    match
      X509.Signing_request.decode_der csr.Tlsa.data,
      X509.Certificate.decode_der cert.Tlsa.data
    with
    | Ok csr, Ok cert ->
      let now_plus_two_weeks =
        let (days, ps) = P.now_d_ps () in
        Ptime.v (days + 14, ps)
      and now = Ptime.v (P.now_d_ps ())
      in
      if Dns_certify.cert_matches_csr ~until:now_plus_two_weeks now csr cert then
        None
      else
        Some csr
    | Ok csr, Error `Msg e ->
      Logs.err (fun m -> m "couldn't parse certificate %s, requesting new one" e);
      Some csr
    | Error `Msg e, _ ->
      Logs.err (fun m -> m "couldn't parse csr %s, nothing to see here" e) ;
      None

  let contains_csr_without_certificate name tlsas =
    let csrs = Rr_map.Tlsa_set.filter Dns_certify.is_csr tlsas in
    if Rr_map.Tlsa_set.cardinal csrs <> 1 then begin
      Logs.warn (fun m -> m "no or multiple signing requests found for %a (skipping)"
                    Domain_name.pp name);
      None
    end else
      let csr = Rr_map.Tlsa_set.choose csrs in
      let certs = Rr_map.Tlsa_set.filter Dns_certify.is_certificate tlsas in
      match Rr_map.Tlsa_set.cardinal certs with
      | 0 ->
        Logs.warn (fun m -> m "no certificate found for %a, requesting"
                      Domain_name.pp name);
        begin match X509.Signing_request.decode_der csr.Tlsa.data with
          | Ok csr -> Some csr
          | Error `Msg e ->
            Logs.warn (fun m -> m "couldn't parse CSR %s" e);
            None
        end
      | 1 ->
        begin
          let cert = Rr_map.Tlsa_set.choose certs in
          match valid_and_matches_csr csr cert with
          | None ->
            Logs.debug (fun m -> m "certificate already exists for signing request %a, skipping"
                           Domain_name.pp name);
            None
          | Some csr ->
            Logs.warn (fun m -> m "certificate not valid or doesn't match signing request %a, requesting"
                          Domain_name.pp name);
            Some csr
        end
      | _ ->
        Logs.err (fun m -> m "multiple certificates found for %a, skipping"
                     Domain_name.pp name);
        None

  let mem_flight, add_flight, remove_flight =
    (* TODO use a map with number of attempts *)
    let in_flight = ref Domain_name.Set.empty in
    (fun x -> Domain_name.Set.mem x !in_flight),
    (fun n ->
       Logs.info (fun m -> m "adding %a to in_flight" Domain_name.pp n);
       in_flight := Domain_name.Set.add n !in_flight),
    (fun n ->
       Logs.info (fun m -> m "removing %a from in_flight" Domain_name.pp n);
       in_flight := Domain_name.Set.remove n !in_flight)

  let send_dns, recv_dns =
    let flow = ref None in
    (fun stack data ->
       let dns_server = Key_gen.dns_server ()
       and port = Key_gen.port ()
       in
       Logs.debug (fun m -> m "writing to %a" Ipaddr.pp dns_server) ;
       let tcp = S.tcp stack in
       let rec send again =
         match !flow with
         | None ->
           if again then
             S.TCP.create_connection tcp (dns_server, port) >>= function
             | Error e ->
               Logs.err (fun m -> m "failed to create connection to NS: %a" S.TCP.pp_error e) ;
               Lwt.return (Error (`Msg (Fmt.to_to_string S.TCP.pp_error e)))
             | Ok f -> flow := Some (D.of_flow f) ; send false
           else
             Lwt.return_error (`Msg "couldn't reach authoritative nameserver")
         | Some f ->
           D.send_tcp (D.flow f) data >>= function
           | Error () -> flow := None ; send again
           | Ok () -> Lwt.return_ok ()
       in
       send true),
    (fun () ->
       (* we expect a single reply! *)
       match !flow with
       | None -> Lwt.return_error (`Msg "no TCP flow")
       | Some f ->
         D.read_tcp f >|= function
         | Ok data -> Ok data
         | Error () -> Error (`Msg "error while reading from flow"))

  module Cstruct_set = Set.Make (struct
      type t = Cstruct.t
      let compare = Cstruct.compare
    end)

  let request_certificate stack (keyname, keyzone, dnskey) server le ctx ~tlsa_name csr =
    if mem_flight tlsa_name then
      Logs.err (fun m -> m "request with %a already in-flight"
                   Domain_name.pp tlsa_name)
    else begin
      Logs.info (fun m -> m "running let's encrypt service for %a"
                    Domain_name.pp tlsa_name);
      add_flight tlsa_name;
      (* request new cert in async *)
      Lwt.async (fun () ->
          let sleep n = T.sleep_ns (Duration.of_sec n) in
          let now () = Ptime.v (P.now_d_ps ()) in
          let id = Randomconv.int16 R.generate in
          let solver = Letsencrypt_dns.nsupdate ~proto:`Tcp id now (send_dns stack) ~recv:recv_dns ~zone:keyzone ~keyname dnskey in
          Acme.sign_certificate ~ctx solver le sleep csr >>= function
          | Error (`Msg e) ->
            Logs.err (fun m -> m "error %s while signing %a" e Domain_name.pp tlsa_name);
            remove_flight tlsa_name;
            Lwt.return_unit
          | Ok [] ->
            Logs.err (fun m -> m "received an empty certificate chain for %a" Domain_name.pp tlsa_name);
            remove_flight tlsa_name;
            Lwt.return_unit
          | Ok (cert::cas) ->
            Logs.info (fun m -> m "certificate received for %a" Domain_name.pp tlsa_name);
            match Dns_trie.lookup tlsa_name Rr_map.Tlsa (Dns_server.Secondary.data server) with
            | Error e ->
              Logs.err (fun m -> m "lookup error for tlsa %a: %a (expected the signing request!)"
                           Domain_name.pp tlsa_name Dns_trie.pp_e e);
              remove_flight tlsa_name;
              Lwt.return_unit
            | Ok (_, tlsas) ->
              (* from tlsas, we need to remove the end entity certificates *)
              (* also potentially all CAs that are not part of cas *)
              (* we should add the new certificate and potentially CAs *)
              let ca_set = Cstruct_set.of_list (List.map X509.Certificate.encode_der cas) in
              let to_remove, cas_to_add =
                Rr_map.Tlsa_set.fold (fun tlsa (to_rm, to_add) ->
                    if Dns_certify.is_ca_certificate tlsa then
                      if Cstruct_set.mem tlsa.Tlsa.data to_add then
                        to_rm, Cstruct_set.remove tlsa.Tlsa.data to_add
                      else
                        tlsa :: to_rm, to_add
                    else if Dns_certify.is_certificate tlsa then
                      tlsa :: to_rm, to_add
                    else
                      to_rm, to_add)
                  tlsas ([], ca_set)
              in
              let update =
                let add =
                  let tlsas =
                    let cas = List.map Dns_certify.ca_certificate (Cstruct_set.elements cas_to_add) in
                    Rr_map.Tlsa_set.of_list (Dns_certify.certificate cert :: cas)
                  in
                  Packet.Update.Add Rr_map.(B (Tlsa, (3600l, tlsas)))
                and remove =
                  List.map (fun tlsa ->
                      Packet.Update.Remove_single Rr_map.(B (Tlsa, (0l, Tlsa_set.singleton tlsa))))
                    to_remove
                in
                let update = Domain_name.Map.singleton tlsa_name (remove @ [ add ]) in
                (Domain_name.Map.empty, update)
              and zone = Packet.Question.create keyzone Rr_map.Soa
              and header = (Randomconv.int16 R.generate, Packet.Flags.empty)
              in
              let packet = Packet.create header zone (`Update update) in
              match Dns_tsig.encode_and_sign ~proto:`Tcp packet (now ()) dnskey keyname with
              | Error s ->
                remove_flight tlsa_name;
                Logs.err (fun m -> m "Error %a while encoding and signing %a"
                             Dns_tsig.pp_s s Domain_name.pp tlsa_name);
                Lwt.return_unit
              | Ok (data, mac) ->
                send_dns stack data >>= function
                | Error (`Msg e) ->
                  remove_flight tlsa_name;
                  Logs.err (fun m -> m "error %s while sending nsupdate %a"
                               e Domain_name.pp tlsa_name);
                  Lwt.return_unit
                | Ok () ->
                  recv_dns () >|= function
                  | Error (`Msg e) ->
                    remove_flight tlsa_name;
                    Logs.err (fun m -> m "error %s while reading DNS %a"
                                 e Domain_name.pp tlsa_name)
                  | Ok data ->
                    remove_flight tlsa_name;
                    match Dns_tsig.decode_and_verify (now ()) dnskey keyname ~mac data with
                    | Error e ->
                      Logs.err (fun m -> m "error %a while decoding nsupdate answer %a"
                                   Dns_tsig.pp_e e Domain_name.pp tlsa_name)
                    | Ok (res, _, _) ->
                      match Packet.reply_matches_request ~request:packet res with
                      | Ok _ -> ()
                      | Error e ->
                        (* TODO: if badtime, adjust our time (to the other time) and resend ;) *)
                        Logs.err (fun m -> m "invalid reply %a for %a, got %a"
                                     Packet.pp_mismatch e Packet.pp packet
                                     Packet.pp res))
    end

  let start _random _pclock _mclock _ stack ctx =
    let keyname, keyzone, dnskey =
      let keyname, dnskey =
        err_to_exit ~prefix:"couldn't parse dnskey"
          (Dnskey.name_key_of_string (Key_gen.dns_key ()))
      in
      let idx =
        err_to_exit ~prefix:"dnskey is not an update key"
          (Option.to_result
             ~none:(`Msg "couldn't find _update label")
             (Domain_name.find_label keyname (function "_update" -> true | _ -> false)))
      in
      let amount = succ idx in
      let zone = Domain_name.(host_exn (drop_label_exn ~amount keyname)) in
      Logs.app (fun m -> m "using key %a for zone %a" Domain_name.pp keyname Domain_name.pp zone);
      keyname, zone, dnskey
    in
    let dns_state = ref
        (Dns_server.Secondary.create ~primary:(Key_gen.dns_server ()) ~rng:R.generate
           ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign [ keyname, dnskey ])
    in
    let account_key =
      let key_type =
        err_to_exit
          ~prefix:"cannot decode key type"
          (X509.Key_type.of_string (Key_gen.account_key_type ()))
      in
      err_to_exit
        ~prefix:"couldn't generate account key"
        (X509.Private_key.of_string ~bits:(Key_gen.account_bits ()) key_type (Key_gen.account_key_seed ()))
    in
    let endpoint =
      if Key_gen.production () then begin
        Logs.warn (fun m -> m "production environment - take care what you do");
        Letsencrypt.letsencrypt_production_url
      end else begin
        Logs.warn (fun m -> m "staging environment - test use only");
        Letsencrypt.letsencrypt_staging_url
      end
    in
    let email = Key_gen.email () in
    Acme.initialise ~ctx ~endpoint ?email account_key >>= fun r ->
    let le = err_to_exit ~prefix:"couldn't initialize ACME" r in
    Logs.info (fun m -> m "initialised lets encrypt");
    let on_update ~old:_ t =
      dns_state := t;
      (* what to do here?
         foreach TLSA record (can as well just do all for now), check whether
         there is a CSR without a valid certificate: if not, request a certificate *)
      let trie = Dns_server.Secondary.data t in
      Dns_trie.fold Dns.Rr_map.Tlsa trie
        (fun name (_, tlsas) () ->
           if Dns_certify.is_name name then
             match contains_csr_without_certificate name tlsas with
             | None -> Logs.debug (fun m -> m "not interesting (does not contain CSR without valid certificate) %a" Domain_name.pp name)
             | Some csr -> request_certificate stack (keyname, keyzone, dnskey) t le ctx ~tlsa_name:name csr
           else
             Logs.debug (fun m -> m "name not interesting %a" Domain_name.pp name)) ();
      Lwt.return_unit
    in
    Lwt.async (fun () ->
        let rec forever () =
          T.sleep_ns (Duration.of_day 1) >>= fun () ->
          on_update ~old:(Dns_server.Secondary.data !dns_state) !dns_state >>= fun () ->
          forever ()
        in
        forever ());
    DS.secondary ~on_update stack !dns_state ;
    S.listen stack
end
