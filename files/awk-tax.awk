function tax(price){
			tx=20;
			return ((price * tx)/100)+price
}

BEGIN {
			print "ENTER PRICE:"
			getline p < "-"
			print "Tax = " tax(p)
}
