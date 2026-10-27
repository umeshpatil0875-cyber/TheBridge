# FIX 8: SSH is only open to the company network, and everything is described.
resource "aws_security_group" "web" {
  name        = "web"
  description = "Web server access"
  ingress {
    description = "SSH from the office network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
