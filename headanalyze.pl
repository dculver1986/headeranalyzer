#$ua->ssl_opts(
#      SSL_verify_mode => "IO::Socket::SSL::SSL_VERIFY_NONE",
#      verify_hostname => 0
#    );
#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use LWP::UserAgent;
use HTTP::Response;

# Constants
my $DEFAULT_OUTPUT_FILE = "http_headers.txt";

# Helper function to print usage instructions
sub usage {
    print "Usage: $0 -u <url> [-o <output_file>]\n";
    print "  -u, --url       URL to analyze HTTP headers for (required).\n";
    print "  -o, --output    Path to the output file (optional, default: $DEFAULT_OUTPUT_FILE).\n";
    print "  -h, --help      Display this help message.\n";
    exit;
}

# Main function
sub main {
    my ($url, $output_file, $help);

    # Configure command-line options
    GetOptions(
        "url=s"    => \$url,
        "output=s" => \$output_file,
        "help"     => \$help,
        "u=s"      => \$url,
        "o=s"      => \$output_file,
        "h"        => \$help,
    ) or usage();

    # Display help if requested or if no URL is provided
    usage() if $help || !$url;

    # Set default output file if not provided
    $output_file ||= $DEFAULT_OUTPUT_FILE;

    print "Analyzing HTTP headers for: $url\n";
    print "Output file: $output_file\n";

    my $response = get_http_response($url); # Get the full response
    my $headers = $response->headers;

    if ($headers) {
        print "\nHTTP Headers:\n";
        open my $fh, '>', $output_file or die "Could not open file '$output_file': $!";
        foreach my $header (keys %$headers) {
            my $value = $headers->{$header};
            print "$header: $value\n";
            print $fh "$header: $value\n";
        }
        close $fh;
        print "\nHTTP headers written to $output_file\n";

        print "\nSecurity Assessment:\n";
        my %security_issues = check_security_headers($headers); # Check security headers
        if (%security_issues) {
            foreach my $issue (keys %security_issues) {
                print "  $issue: $security_issues{$issue}\n";
            }
        } else {
            print "  No security concerns detected.\n";
        }
    } else {
        print "\nFailed to retrieve HTTP headers.\n";
    }
}

# Function to get the full HTTP response
sub get_http_response {
    my ($url) = @_;
    my $ua = LWP::UserAgent->new;
    $ua->ssl_opts(
      SSL_verify_mode => "IO::Socket::SSL::SSL_VERIFY_NONE",
      verify_hostname => 0
    );
    $ua->agent("MyHTTPHeaderAnalyzer/0.1");
    my $response = $ua->get($url); # Use GET to get the full response

    if ($response->is_success) {
        return $response;
    } else {
        warn "Error fetching response: " . $response->status_line . "\n";
        return undef;
    }
}
# Function to get HTTP headers
sub get_http_headers {
    my ($url) = @_;
    my $ua = LWP::UserAgent->new;
    $ua->agent("MyHTTPHeaderAnalyzer/0.1"); # Set a custom user agent.
    my $response = $ua->head($url); # Use HEAD request for headers only

    if ($response->is_success) {
        # Use the HTTP::Response object to access headers.  This handles
        # the case where a header might have multiple values correctly.
        my %headers;
        foreach my $header_name ($response->header_field_names) {
             $headers{$header_name} = $response->header($header_name); #Gets all values for header
        }
        return \%headers;
    } else {
        warn "Error fetching headers: " . $response->status_line . "\n";
        return undef; # Explicitly return undef on failure
    }
}

# Function to check for common security-related headers
sub check_security_headers {
    my ($headers) = @_;
    my %issues;

    # Check for Strict-Transport-Security (HSTS)
    if (!exists $headers->{'Strict-Transport-Security'}) {
        $issues{'HSTS'} = "Not present.  Should be enabled for HTTPS sites.";
    } elsif ($headers->{'Strict-Transport-Security'} !~ /max-age=\d+/) {
        $issues{'HSTS'} = "Missing max-age directive.";
    }

    # Check for Content-Security-Policy (CSP)
    if (!exists $headers->{'Content-Security-Policy'}) {
        $issues{'CSP'} = "Not present.  Should be configured to prevent XSS.";
    }

    # Check for X-Frame-Options
    if (!exists $headers->{'X-Frame-Options'}) {
        $issues{'X-Frame-Options'} = "Not present.  Should be set to DENY or SAMEORIGIN to prevent clickjacking.";
    }

    # Check for X-Content-Type-Options
    if (!exists $headers->{'X-Content-Type-Options'}) {
        $issues{'X-Content-Type-Options'} = "Not present.  Should be set to nosniff to prevent MIME sniffing.";
    }

    # Check for Referrer-Policy
    if (!exists $headers->{'Referrer-Policy'}){
        $issues{'Referrer-Policy'} = "Not present. Should be set to control how much referrer information is sent";
    }

    return %issues;
}

# Run the main function
main();

