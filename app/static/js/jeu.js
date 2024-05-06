//lancer de dé -> l.55
var de1;

var face = new Array();

var temps = 0

var setupEvents = function()
	{
	//temps=window.setInterval(afficheDe, 50);

	var stopper=document.getElementById('stopper');
	stopper.addEventListener("click",stop);

	var lancer=document.getElementById('lancer');
	lancer.addEventListener("click",unstop);
	}

window.addEventListener("load", setupEvents);


var afficheDe=function()
	{
	for (var i= 1; i<7 ; i++)
		{face[i]=new Image();
		face[i].src = "/static/images/face[" + i + "].png";
		}

	de1 = Math.floor(Math.random() * 6)+1;
	var de=document.getElementById('de');
	de.src = face[de1].src;
	}



var stop = function() {

	window.clearInterval(temps);

	for (var i=1; i<=de1 ; i++)
		{
		var image = document.getElementById(construitId(i));
		image = face[i].src;
		}	

	}

var unstop = function() {

	temps=window.setInterval(afficheDe, 50);

	}

var construitId = function(i)
	{return "image"+i;}
//fin lancer de dé




function avancede3()
{
valeur_de=3;document.getElementById("dede").innerHTML="bonne réponse, vous avancez de 3 cases";cazesansquestion();
}
function reculde3()
{valeur_de=-3;document.getElementById("dede").innerHTML="mauvaise réponse, vous reculez de 3 cases";cazesansquestion();
}

function caze()
{
valeur_case+=valeur_de;document.getElementById("case").innerHTML="case numero "+ valeur_case;valeurquestion();
}
function cazesansquestion()
{
valeur_case+=valeur_de;document .getElementById("case").innerHTML="case numero "+ valeur_case;
}
function valeurquestion()
{
valeur_question=de1
document.getElementById("valeur_question").innerHTML="question numero "+ valeur_question;question();
}

function question()
{
switch (valeur_question)
{
case 1:
reponse = prompt("quel est le chiffre 1 ??","");
break;
case 2:
reponse = prompt("quel est le chiffre 2 ??","");
break;
case 3:
reponse = prompt("quel est le chiffre 3 ??","");
break;
case 4:
reponse = prompt("quel est le chiffre 4 ??","");
break;
case 5:
reponse = prompt("quel est le chiffre 5 ??","");
break;
case 6:
reponse = prompt("quel est le chiffre 6 ??","");
break; case 7:
reponse = prompt("quel est le chiffre 7 ??","");
break;
case 8:
reponse = prompt("quel est le chiffre 8 ??","");
break;
case 9:
reponse = prompt("quel est le chiffre 9 ??","");
break;
case 10:
reponse = prompt("quel est le chiffre 10 ??","");
break;
case 11:
reponse = prompt("quel est le chiffre 11 ??","");
break;
case 12:
reponse = prompt("quel est le chiffre 12 ??","");
break;
case 13:
reponse = prompt("quel est le chiffre 13 ??","");
break;
case 14:
reponse = prompt("quel est le chiffre 14 ??","");
break;
case 15:
reponse = prompt("quel est le chiffre 15 ??","");
break;
case 16:
reponse = prompt("quel est le chiffre 16 ??","");
break;
case 17:
reponse = prompt("quel est le chiffre 17 ??","");
break;
case 18:
reponse = prompt("quel est le chiffre 18 ??","");
break;
case 19:
reponse = prompt("quel est le chiffre 19 ??","");
break;
case 20:
reponse = prompt("quel est le chiffre 20 ??","");
break;
case 21:
reponse = prompt("quel est le chiffre 21 ??","");
break;
case 22:
reponse = prompt("quel est le chiffre 22 ??","");
break;
case 23:
reponse = prompt("quel est le chiffre 23 ??","");
break;
case 24:
reponse = prompt("quel est le chiffre 24 ??","");
break;
case 25:
reponse = prompt("quel est le chiffre 25 ??","");
break;

}
verifreponse();
}

function verifreponse()
{
if (valeur_question==1)if (reponse==1)avancede3();else reculde3();
if (valeur_question==2)if (reponse==2)avancede3();else reculde3();
if (valeur_question==3)if (reponse==3)avancede3();else reculde3();
if (valeur_question==4)if (reponse==4)avancede3();else reculde3();
if (valeur_question==5)if (reponse==5)avancede3();else reculde3();
if (valeur_question==6)if (reponse==6)avancede3();else reculde3();
}