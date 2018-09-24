'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getZoneFileTemplate = getZoneFileTemplate;
function getZoneFileTemplate() {
  return '{$origin}\n\
{$ttl}\n\
\n\
; SOA Record\n\
{name} {ttl}    IN  SOA {mname}{rname}(\n\
{serial} ;serial\n\
{refresh} ;refresh\n\
{retry} ;retry\n\
{expire} ;expire\n\
{minimum} ;minimum ttl\n\
)\n\
\n\
; NS Records\n\
{ns}\n\
\n\
; MX Records\n\
{mx}\n\
\n\
; A Records\n\
{a}\n\
\n\
; AAAA Records\n\
{aaaa}\n\
\n\
; CNAME Records\n\
{cname}\n\
\n\
; PTR Records\n\
{ptr}\n\
\n\
; TXT Records\n\
{txt}\n\
\n\
; SRV Records\n\
{srv}\n\
\n\
; SPF Records\n\
{spf}\n\
\n\
; URI Records\n\
{uri}\n\
';
}