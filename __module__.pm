#
# (c) FILIADATA GmbH
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Trocla;

use Moose;

use Rex::Commands::Run;
require Rex::Commands;

has host => (
  is => 'ro',
  default => sub { "<local>" },
);

sub get {
  my ($self, $key, $format) = @_;
  $format ||= "plain";

  my $ret = Rex::Commands::run_task("get_password", on => $self->host, params => { password => $key, format => $format });
  return $ret;
}

Rex::Commands::task("get_password", sub {
  my $param = shift;
  my $key = $param->{password};
  my $format = $param->{format};

  if(ref $key eq "ARRAY") {
    my $ret = {};
    for my $k (@{ $key }) {
      $ret->{$k} = run "trocla get '$k' $format";
    }
    return $ret;
  }
  else {
    my $out = run "trocla get '$key' $format";
    return $out;
  }

});

1;

=pod

=head1 NAME

Trocla - Interact with trocla for password management.

=head1 DESCRIPTION

Trocla is a tool to manage your passwords on a central server. You can generate passwords on the fly and query trocla during configuration management runs. Trocla will store your passwords in a secure way. See L<https://github.com/duritong/trocla>.

=head1 SYNOPSIS

 use Trocla;
   
 task "prepare", "host01", sub {
   my $trocla = Trocla->new(host => "trocla-server");
   my $db_pw = $trocla->get("db-password-" . connection->server);
 };

=head1 COPYRIGHT

Copyright 2015 FILIADATA GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


