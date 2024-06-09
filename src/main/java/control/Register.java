package control;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import model.DriverManagerConnectionPool;


@WebServlet("/Register")
public class Register extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    
    public Register() {
        super();
    }

	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String email = request.getParameter("email");
		String password = request.getParameter("password");
		String nome = request.getParameter("nome");
		String cognome = request.getParameter("cognome");
		String indirizzo = request.getParameter("indirizzo");
		String telefono = request.getParameter("telefono");
		String carta = request.getParameter("carta");
		String intestatario = request.getParameter("intestatario");
		String cvv = request.getParameter("cvv");
		String redirectedPage = "/loginPage.jsp";
		
		Connection con = null;
		try {
			con = DriverManagerConnectionPool.getConnection();
			con.setAutoCommit(false); 
			
			String sql = "INSERT INTO UserAccount(email, passwordUser, nome, cognome, indirizzo, telefono, numero, intestatario, CVV) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
			String sql2 = "INSERT INTO Cliente(email) VALUES (?)";
			String sql3 = "INSERT INTO Venditore(email) VALUES (?)";
			
			
			PreparedStatement ps = con.prepareStatement(sql);
			ps.setString(1, email);
			ps.setString(2, hashPassword(password, "SHA-256")); 
			ps.setString(3, nome);
			ps.setString(4, cognome);
			ps.setString(5, indirizzo);
			ps.setString(6, telefono);
			ps.setString(7, carta);
			ps.setString(8, intestatario);
			ps.setString(9, cvv);
			
			ps.executeUpdate();
			
			
			PreparedStatement ps2 = con.prepareStatement(sql2);
			ps2.setString(1, email);
			ps2.executeUpdate();
			
			
			PreparedStatement ps3 = con.prepareStatement(sql3);
			ps3.setString(1, email);
			ps3.executeUpdate();
			
			con.commit(); 
			
		} catch (SQLException e) {
			if (con != null) {
				try {
					con.rollback(); 
				} catch (SQLException ex) {
					ex.printStackTrace();
				}
			}
			request.getSession().setAttribute("register-error", true);
			redirectedPage = "/register-form.jsp";
		} finally {
			if (con != null) {
				try {
					DriverManagerConnectionPool.releaseConnection(con);
				} catch (SQLException e) {
					e.printStackTrace();
				}
			}
		}
		
		response.sendRedirect(request.getContextPath() + redirectedPage);
	}

	private String hashPassword(String password, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] messageDigest = md.digest(password.getBytes());
			BigInteger number = new BigInteger(1, messageDigest);
			String hashtext = number.toString(16);

		
			while (hashtext.length() < (md.getDigestLength() * 2)) {
				hashtext = "0" + hashtext;
			}

			return hashtext;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
