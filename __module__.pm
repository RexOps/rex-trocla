#
# (c) FILIADATA GmbH
# 
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Trocla;

use Moose;

use Rex::Commands::Run;
use Rex::Commands::File;
use YAML;
require Rex::Commands;

has host => (
  is      => 'ro',
  default => sub { "<local>" },
);

has trocla_db_file => (
  is      => 'ro',
  default => sub { "/var/lib/trocla/data.yaml" },
);

sub get {
  my ($self, $key, $format) = @_;
  $format ||= "plain";

  my $ret = Rex::Commands::run_task("Trocla:get_password", on => $self->host, params => { password => $key, format => $format });
  return $ret;
}

sub mget {
  my ($self, $regexp) = @_;
  my $keys = $self->keys;

  my @query;
  for my $k (@{ $keys }) {
    if($k =~ $regexp) {
      push @query, $k;
    }
  }

  return $self->get(\@query);
}

sub keys {
  my ($self) = @_;
  my $ret = Rex::Commands::run_task("Trocla:list_keys", on => $self->host, params => { file => $self->trocla_db_file });
  return $ret;
}

sub create {
  my ($self, $name, $format, $options) = @_;
  my $ret = Rex::Commands::run_task("Trocla:create_key", on => $self->host, params => { name => $name, format => $format, options => $options });
}

Rex::Commands::task("create_key", sub {
  my $param = shift;
  
  my $name = $param->{name};
  my $format = $param->{format} || "plain";
  my $options = $param->{options} || { format => "alphanumeric" };
  
  my $cmd = "/usr/local/bin/trocla create '$name' $format";
  
  if($options) {
    $cmd .= " '";
    for my $opt (CORE::keys(%{$options})) {
      $cmd .= "$opt: " . $options->{$opt} . "\n";
    }
    
    $cmd .= "'";
  }
  
  my $out;
  sudo sub {
    $out = run $cmd;
  };
  
  if($? != 0) {
    die "Error creating trocla key: $name.\nOUT: $out\n";
  }
  
  return $out;
});

Rex::Commands::task("list_keys", sub {
  my $param = shift;
  my $file  = $param->{file};

  my $ret = [];

  sudo sub {
    my $file_content = cat $file;
    my $ref = YAML::Load($file_content . "\n");
    $ret = [ CORE::keys(%{ $ref }) ];
  };

  return $ret;
});

Rex::Commands::task("get_password", sub {
  my $param = shift;
  my $key = $param->{password};
  my $format = $param->{format};

  my $ret;
  sudo sub {

    if(ref $key eq "ARRAY") {
      $ret = {};
      for my $k (@{ $key }) {
        $ret->{$k} = run "/usr/local/bin/trocla get '$k' $format";
      }
    }
    else {
      my $out = run "/usr/local/bin/trocla get '$key' $format";
      $ret = $out;
    }

  };

  return $ret;

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


