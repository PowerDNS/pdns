function updatepolicy(arg)
  princ = arg:getPeerPrincipal()
  return princ == "testuser2@EXAMPLE.COM"
end
