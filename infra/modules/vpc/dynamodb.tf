resource "aws_dynamodb_table_item" "example" {
  table_name = aws_dynamodb_table.example.name
  hash_key   = aws_dynamodb_table.example.hash_key


  item = <<ITEM
{
  "${var.dynamodb_table_name}": {"S": "${var.env}"},
  "vpc_app_cidr": {"S": "${aws_vpc.this.cidr_block}"},
  "vpc_data_cidr": {"S": "10.10.0.0/16"}
}
ITEM
}

resource "aws_dynamodb_table" "example" {
  name           = var.dynamodb_table_name
  read_capacity  = 10
  write_capacity = 10
  hash_key       = var.dynamodb_table_name

  attribute {
    name = var.dynamodb_table_name
    type = "S"
  }
}
