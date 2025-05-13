$(document).ready(function(){
	// var percent 	= [4.08,5.04,6];
	// var minMoney 	= [0.01,1.01,25.01];
	// var maxMoney	= [1.00,25.00,99999];
	var Hourly		= [0.17,0.21,0.25];
	// $("#money").val(minMoney[0]);
	
	//Calculator
	function calc1(){
		var minMoney = [0.01];
		var maxMoney = [1]
		var percent 	= [4.08];
		money1 = parseFloat($("#money1").val());
		id = -1;
		var length = percent.length;
		var i = 0;
		do {
			if(minMoney[i] <= money1 && money1 <= maxMoney[i]){
				id = i;
				i = i + length;
			}
			i++
		}
		while(i < length)
		
		if(id != -1){
			profitDaily = money1 / 100 * percent[id];
			profitDaily = profitDaily.toFixed(8);
			profitHourly = profitDaily /24;
			profitHourly = profitHourly.toFixed(8);
			profitWeekly = profitDaily * 7;
			profitWeekly = profitWeekly.toFixed(8);
			profitMonthly = profitDaily * 30;
			profitMonthly = profitMonthly.toFixed(8);
			summa = profitDaily *30;
			summa = summa.toFixed(8);


			if(money1 < minMoney[id] || isNaN(money1) == true){
				$("#profit").text("Error!");
				$("#profitHourly").text("Error!");
				$("#profitDaily").text("Error!");
				$("#profitWeekly").text("Error!");
				$("#profitMonthly").text("Error!");
			} else {
				$("#profit").text(summa);
				$("#profitHourly").text(profitHourly);
				$("#profitDaily").text(profitDaily);
				$("#profitWeekly").text(profitWeekly);
				$("#profitMonthly").text(profitMonthly);
			}
		} else {
			$("#profit").text("Error!");
			$("#profitHourly").text("Error!");
			$("#profitDaily").text("Error!");
			$("#profitWeekly").text("Error!");
			$("#profitMonthly").text("Error!");
		}
	}//Calculator
	function calc2(){
		var minMoney = [1.01];
		var maxMoney = [25]
		var percent 	= [5.04];
		money2 = parseFloat($("#money2").val());
		id = -1;
		var length = percent.length;
		var i = 0;
		do {
			if(minMoney[i] <= money2 && money2 <= maxMoney[i]){
				id = i;
				i = i + length;
			}
			i++
		}
		while(i < length)
		
		if(id != -1){
			profitDaily2 = money2 / 100 * percent[id];
			profitDaily2 = profitDaily2.toFixed(8);
			profitHourly2 = profitDaily2 / 24;
			profitHourly2 = profitHourly2.toFixed(8);
			profitWeekly2 = profitDaily2 * 7;
			profitWeekly2 = profitWeekly2.toFixed(8);
			profitMonthly2 = profitDaily2 * 30;
			profitMonthly2 = profitMonthly2.toFixed(8);
			summa = profitDaily2 *30;
			summa = summa.toFixed(8);


			if(money2 < minMoney[id] || isNaN(money2) == true){
				$("#profit2").text("Error!");
				$("#profitHourly2").text("Error!");
				$("#profitDaily2").text("Error!");
				$("#profitWeekly2").text("Error!");
				$("#profitMonthly2").text("Error!");
			} else {
				$("#profit2").text(summa);
				$("#profitHourly2").text(profitHourly2);
				$("#profitDaily2").text(profitDaily2);
				$("#profitWeekly2").text(profitWeekly2);
				$("#profitMonthly2").text(profitMonthly2);
			}
		} else {
			$("#profit2").text("Error!");
			$("#profitHourly2").text("Error!");
			$("#profitDaily2").text("Error!")
			$("#profitWeekly2").text("Error!");
			$("#profitMonthly2").text("Error!");
		}
	}//Calculator
	function calc3(){
		var minMoney = [25.01];
		var maxMoney = [9999999]
		var percent 	= [6];
		money3 = parseFloat($("#money3").val());
		id = -1;
		var length = percent.length;
		var i = 0;
		do {
			if(minMoney[i] <= money3 && money3 <= maxMoney[i]){
				id = i;
				i = i + length;
			}
			i++
		}
		while(i < length)
		
		if(id != -1){
			profitDaily3 = money3 / 100 * percent[id];
			profitDaily3 = profitDaily3.toFixed(8);
			profitHourly3 = profitDaily3 /24;
			profitHourly3 = profitHourly3.toFixed(8);
			profitWeekly3 = profitDaily3 * 7;
			profitWeekly3 = profitWeekly3.toFixed(8);
			profitMonthly3 = profitDaily3 * 30;
			profitMonthly3 = profitMonthly3.toFixed(8);
			summa = profitDaily3 *30;
			summa = summa.toFixed(8);


			if(money3 < minMoney[id] || isNaN(money3) == true){
				$("#profit3").text("Error!");
				$("#profitHourly3").text("Error!");
				$("#profitDaily3").text("Error!");
				$("#profitWeekly3").text("Error!");
				$("#profitMonthly3").text("Error!");
			} else {
				$("#profit3").text(summa);
				$("#profitHourly3").text(profitHourly3);
				$("#profitDaily3").text(profitDaily3);
				$("#profitWeekly3").text(profitWeekly3);
				$("#profitMonthly3").text(profitMonthly3);
			}
		} else {
			$("#profit3").text("Error!");
			$("#profitHourly3").text("Error!");
			$("#profitDaily3").text("Error!");
			$("#profitWeekly3").text("Error!");
			$("#profitMonthly3").text("Error!");
		}
	}
	if($("#money1").length){
		calc1();
	}
	if($("#money2").length){
		calc2();
	}
	if($("#money3").length){
		calc3();
	}
	$("#money1").keyup(function(){
		calc1();
	});
	$("#money2").keyup(function(){
		calc2();
	});
	$("#money3").keyup(function(){
		calc3();
	});
	
$(function () {
  $('[data-toggle="tooltip"]').tooltip()
})
});