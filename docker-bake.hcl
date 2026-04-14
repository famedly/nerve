variable "TAG" {
  default = "latest"
}

variable "REGISTRY" {
  default = "registry.famedly.net/docker-nightly"
}

group "default" {
  targets = ["nerve"]
}

target "nerve" {
  target = "nerve"
  tags = ["${REGISTRY}/nerve:${TAG}"]
}
