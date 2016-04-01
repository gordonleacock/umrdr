module Umrdr

  # For local development you can use the https://www.incommon.org/cert/repository/InCommonServerCA.txt
  # as a certiticate for verifying the MCommunity LDAP server's certificate.
  # ENV['LDAPTLS_CACERT'] = '/www/www.lib/misc/bundle.crt';

  require 'rubygems'
  require 'net/ldap'

  class UniqnameLdapRoles

    attr_accessor :uniqname

    def self.uniqname_faculty_or_staff?(uname)
      Umrdr::UniqnameLdapRoles.new(uname).run
    end

    def initialize(uname)
      # set uniqname for search
      @uniqname = uname
    end

    def faculty_or_staff_roles?(umichinstroles)
      faculty = staff = student = false

      umichinstroles.each do |value|
        faculty = value.downcase.include? "faculty"
        staff = value.downcase.include? "regularstaff"
        student = value.downcase.include? "student"
      end

      if faculty
        return true
      elsif (staff && ! student)
        return true
      else
        return false
      end

    end

    # Errors returned rescue from ldap.open in run method can include
    # "getaddrinfo: nodename nor servname provided, or not known" when HOST is wrong
    # "Operation timed out - user specified timeout" when PORT is wrong
    # "undefined method `umichinstroles' for #<Net::LDAP::Entry:OBJECT-NUMBER>" when  USERNAME is wrong
    # "undefined method `umichinstroles' for #<Net::LDAP::Entry:OBJECT-NUMBER>" when  PASSWORD is wrong
    # "Error: Invalid binding information" when the AUTH is wrong

    def run
      begin
        @ldap = Net::LDAP.open(:host => Umrdr::LdapConfig.host, :port => Umrdr::LdapConfig.port, :encryption => Umrdr::LdapConfig.encryption, :auth => Umrdr::LdapConfig.auth) do |ldap|
          # set up search
          filter = Net::LDAP::Filter.eq('objectclass', '*')
          treebase = "uid=#{@uniqname},ou=People,dc=umich,dc=edu"

          ldap.search( :base => treebase, :filter => filter ) do |entry|
            
            return faculty_or_staff_roles?(entry.umichinstroles)

          end # do |entry|

          return false  # for the case when there is no entry, e.g. uniqname zzzzzz
        end # do |ldap|

      rescue Exception, StandardError, Net::LDAP::ConnectionError, Net::LDAP::Error, SocketError, SystemCallError, OpenSSL::SSL::SSLError => e
        raise "LDAP PROBLEM - Error: #{e}"
      end
    end

  end
end