/*
 * Emyzelium (Rust)
 *
 * is another wrapper around ZeroMQ's Publish-Subscribe messaging pattern
 * with mandatory Curve security and optional ZAP authentication filter,
 * over Tor, through Tor SOCKS proxy,
 * for distributed artificial elife, decision making etc. systems where
 * each peer, identified by its public key, onion address, and port,
 * publishes and updates vectors of vectors of bytes of data
 * under unique topics that other peers can subscribe to
 * and receive the respective data.
 * 
 * https://github.com/emyzelium/emyzelium-rs
 * 
 * emyzelium@protonmail.com
 * 
 * Copyright (c) 2023-2024 Emyzelium caretakers
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * Demo
 */

extern crate crossterm;
extern crate rand;

extern crate emyzelium;

use crossterm::{
    cursor::{
        self,
        MoveTo
    },
    event::{
        self,
        Event,
        KeyCode
    },
    execute,
    style::{
        Color,
        Colors,
        Print,
        SetColors
    },
    terminal::{
        self,
        Clear,
        ClearType,
    },
    queue
};

use emyzelium::{
    self as emz,
    Efunguz
};

use rand::prelude::*;

use std::{
    io::{
        stdout,
        Write
    },
    collections::HashSet,
    env,
    time::{
        Duration,
        SystemTime,
        UNIX_EPOCH
    }
};

// Of course, person_SECRETKEY should be known only to that person
// Here they are "revealed" at once for demo purpose

const ALIEN_SECRETKEY: &str = "gr6Y.04i(&Y27ju0g7m0HvhG0:rDmx<Y[FvH@*N(";
const ALIEN_PUBLICKEY: &str = "iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R";
const ALIEN_ONION: &str = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL"; // from service_dir/hostname, without .onion
const ALIEN_PORT: u16 = 60847;

const JOHN_SECRETKEY: &str = "gbMF0ZKztI28i6}ax!&Yw/US<CCA9PLs.Osr3APc";
const JOHN_PUBLICKEY: &str = "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW";
const JOHN_ONION: &str = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL"; // from service_dir/hostname, without .onion
const JOHN_PORT: u16 = 60848;

const MARY_SECRETKEY: &str = "7C*zh5+-8jOI[+^sh[dbVnW{}L!A&7*=j/a*h5!Y";
const MARY_PUBLICKEY: &str = "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0";
const MARY_ONION: &str = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL"; // from service_dir/hostname, without .onion
const MARY_PORT: u16 = 60849;

const DEF_AUTOEMIT_INTERVAL: f64 = 4.0;
const DEF_FRAMERATE: i32 = 30;

struct Other {
    name: String,
    publickey: String
}

#[allow(non_camel_case_types)]
struct Realm_CA {
    name: String,
    efunguz: emyzelium::Efunguz,
    height: i16,
    width: i16,
    cells: Vec<Vec<u8>>,
    birth: HashSet<usize>,
    survival: HashSet<usize>,
    autoemit_interval: f64,
    framerate: i32,
    i_turn: u64,
    cursor_y: i16,
    cursor_x: i16,
    others: Vec<Other>
}

fn time_musec() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_micros() as i64,
        Err(_) => 0
    } 
}

fn init_term_graphics() -> Result<(), String> {
    terminal::enable_raw_mode().map_err(|err| err.to_string())?;
    let _ = execute!(stdout(),
        terminal::EnterAlternateScreen,
        terminal::DisableLineWrap,
        cursor::Hide
    );
    Ok(())
}

fn drop_term_graphics() -> Result<(), String> {
    let _ = execute!(stdout(),
        cursor::Show,
        terminal::EnableLineWrap,
        terminal::LeaveAlternateScreen
    );
    terminal::disable_raw_mode().map_err(|err| err.to_string())
}

fn clear_row_right() {
    let _ = queue!(stdout(),
        Clear(ClearType::UntilNewLine)
    );
}

fn print_str(y: i16, x: i16, s: &str, fc: Color, bc: Color) {
    let _ = queue!(stdout(),
        MoveTo(x as u16, y as u16),
        SetColors(Colors::new(fc, bc)),
        Print(s)
    );
}

fn print_str_def(y: i16, x: i16, s: &str) {
    print_str(y, x, s, Color::Grey, Color::Reset);
}

fn print_rect(y: i16, x: i16, h: i16, w: i16, fc: Color, bc: Color) {
    print_str(y, x, "┌", fc, bc);
	print_str(y, x + w - 1, "┐", fc, bc);
	print_str(y + h - 1, x + w - 1, "┘", fc, bc);
	print_str(y + h - 1, x, "└", fc, bc);
	for i in 1..(h - 1) {
		print_str(y + i, x, "│", fc, bc);
		print_str(y + i, x + w - 1, "│", fc, bc);
	}
	for j in 1..(w - 1) {
		print_str(y, x + j, "─", fc, bc);
		print_str(y + h - 1, x + j, "─", fc, bc);
	}
}

fn print_rect_def(y: i16, x: i16, h: i16, w: i16) {
    print_rect(y, x, h, w, Color::Grey, Color::Reset);
}

impl Other {
    fn new(name: &str, publickey: &str) -> Self {
        Self {
            name: String::from(name),
            publickey: String::from(publickey)
        }
    }
}

impl Realm_CA {
    fn new(name: &str, secretkey: &str, whitelist_publickeys: & HashSet::<String>, pub_port: u16, height: i16, width: i16, birth: & HashSet::<usize>, survival: & HashSet::<usize>, autoemit_interval: f64, framerate: i32) -> Self {
        Self {
            name: String::from(name),
            efunguz: Efunguz::new(secretkey, whitelist_publickeys, pub_port, emz::DEF_TOR_PROXY_PORT, emz::DEF_TOR_PROXY_HOST),
            height,
            width,
            cells: (0..height).map(|_| {
                vec![0u8; width as usize]
            }).collect::<Vec<Vec<u8>>>(),
            birth: birth.clone(),
            survival: survival.clone(),
            autoemit_interval,
            framerate,
            i_turn: 0,
            cursor_y: height >> 1,
            cursor_x: width >> 1,
            others: Vec::new()
        }
    }

    fn add_other(&mut self, name: &str, publickey: &str, onion: &str, port: u16) {
        if let Ok(eh) = self.efunguz.add_ehypha(publickey, onion, port) {
            let _ = eh.add_etale("");
            let _ = eh.add_etale("zone");
        }
        self.others.push(Other::new(name, publickey));
    }

    fn flip(&mut self, y: Option<i16>, x: Option<i16>) {        
        let fy = match y {
            Some(y) => y,
            None => self.cursor_y
        };
        let fx = match x {
            Some(x) => x,
            None => self.cursor_x
        };
        self.cells[fy as usize][fx as usize] ^= 1;
    }

    fn clear(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.cells[y as usize][x as usize] = 0;
            }
        }
        self.i_turn = 0;
    }

    fn reset(&mut self) {
        let mut rng = thread_rng();
        for y in 0..self.height {
            for x in 0..self.width {
                self.cells[y as usize][x as usize] = rng.gen::<u8>() & 1;
            }
        }
        self.i_turn = 0;
    }

    fn render(&self, show_cursor: bool) {
        let h = self.height;
        let w = self.width;
        let w_tert = w / 3;

        print_rect_def(0, 0, (h >> 1) + 2, w + 2);
        print_str_def(0, w_tert, "┬┬");
		print_str_def(0, w - w_tert, "┬┬");
		print_str_def(1 + (h >> 1), w_tert, "┴┴");
		print_str_def(1 + (h >> 1), w - w_tert, "┴┴");
		print_str_def(0, 2, "[ From others ]");
		print_str_def(0, 3 + w - w_tert, "[ To others ]");

        let cell_chars = [[" ", "▀"], ["▄", "█"]];

        for i in 0..((h >> 1) as usize) {
			let y = i << 1;
			let mut row_str = String::new();
			for x in 0..(w as usize) {
				row_str += cell_chars[(self.cells[y + 1][x] & 1) as usize][(self.cells[y][x] & 1) as usize];
            }
			print_str(1 + (i as i16), 1, &row_str, Color::White, Color::Reset); // white on black
		}

        let mut status_str: String = format!("[ T = {}", self.i_turn);

        if show_cursor {
            let i = (self.cursor_y >> 1) as usize;
			let m = (self.cursor_y & 1) as usize;
			let cell_high = (self.cells[i << 1][self.cursor_x as usize] & 1) as usize;
			let cell_low = (self.cells[(i << 1) + 1][self.cursor_x as usize] & 1) as usize;

            let chars = [[["▀", "▄"], ["▀", "▀"]], [["▄", "▄"], ["▄", "▀"]]];
            let fclrs = [[[Color::DarkRed, Color::DarkRed], [Color::DarkYellow, Color::White]], [[Color::White, Color::DarkYellow], [Color::White, Color::White]]];
            let bclrs = [[[Color::Reset, Color::Reset], [Color::Reset, Color::DarkRed]], [[Color::DarkRed, Color::Reset], [Color::DarkYellow, Color::DarkYellow]]];

            let s_char = chars[cell_low][cell_high][m];
            let s_fclr = fclrs[cell_low][cell_high][m];
            let s_bclr = bclrs[cell_low][cell_high][m];

            print_str(1 + (i as i16), 1 + self.cursor_x, s_char, s_fclr, s_bclr);

            status_str += & format!(", X = {}, Y = {}, C = {}", self.cursor_x,  self.cursor_y, self.cells[self.cursor_y as usize][self.cursor_x as usize] & 1);
        }

        status_str += " ]";
        print_str_def(1 + (h >> 1), 1 + ((w - (status_str.len() as i16)) >> 1), &status_str);
    }

    fn move_cursor(&mut self, dy: i16, dx: i16) {
        self.cursor_y = (self.cursor_y + dy).max(0).min(self.height - 1);
        self.cursor_x = (self.cursor_x + dx).max(0).min(self.width - 1);
    }

    fn turn(&mut self) {
		// Not much optimization...
		let h = self.height;
		let w = self.width;
		// Count alive neighbours
		for y in 0..h {
			for x in 0..w {
				if (self.cells[y as usize][x as usize] & 1) != 0 { // increment number of neighbours for all neighbouring cells
					for ny in (y - 1)..=(y + 1) {
						if (ny >= 0) && (ny < h) {
							for nx in (x - 1)..=(x + 1) {
								if ((ny != y) || (nx != x)) && (nx >= 0) && (nx < w) {
									self.cells[ny as usize][nx as usize] += 2; // accumulate in bits 1 and higher
								}
							}
						}
					}
				}
			}
		}
		// Update
		for y in 0..(h as usize) {
			for x in 0..(w as usize) {
				let mut c = self.cells[y][x] as usize;
				if (c & 1) != 0 {
					c = self.survival.contains(&(c >> 1)) as usize;
				} else {
					c = self.birth.contains(&(c >> 1)) as usize;
				}
				self.cells[y][x] = c as u8;
			}
		}
		self.i_turn += 1;
	}

    fn get_parts_from_zone(&self) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        let h = self.height;
        let w = self.width;
        let zh = h;
        let zw = w / 3;
        parts.push(zh.to_le_bytes().to_vec());
        parts.push(zw.to_le_bytes().to_vec());
        parts.push(vec![0u8; (zh * zw) as usize]);
        for y in 0..(zh as usize) {
            for x in 0..(zw as usize) {
                parts[2][y * (zw as usize) + x] = self.cells[y][((w - zw) as usize) + x] & 1;
            }
        }
        parts
    }

    fn put_parts_to_zone(&mut self, parts: & Vec<Vec<u8>>) {
        if parts.len() == 3 {
            if (parts[0].len() == 2) && (parts[1].len() == 2) {
                let szh = i16::from_le_bytes([parts[0][0], parts[0][1]]);
                let szw = i16::from_le_bytes([parts[1][0], parts[1][1]]);
                if parts[2].len() == (szh as usize) * (szw as usize) {
                    let dzh = szh.min(self.height);
                    let dzw = szw.min(self.width / 3);
                    for y in 0..(dzh as usize) {
                        for x in 0..(dzw as usize) {
                            self.cells[y][x] = parts[2][y * (szw as usize) + x] & 1;
                        }
                    }
                }
            }
        }
    }

    fn emit_etales(&mut self) {
        self.efunguz.emit_etale("", & vec![
            "zone".as_bytes().to_vec(),
            "2B height (h), 2B width (w), h×wB zone by rows".as_bytes().to_vec()
        ]);
        self.efunguz.emit_etale("zone", & self.get_parts_from_zone());
    }

    fn update_efunguz(&mut self) {
        self.efunguz.update();
    }

    fn run(&mut self) {
        let (n_rows, _n_columns) = match terminal::size() {
            Ok((w, h)) => (h as i16, w as i16),
            _ => (0, 0)
        };

        let h = self.height;
        // let w = self.width;

        let mut quit = false;
        let mut paused = false;
        let mut render = true;
        let mut autoemit = true;

        let t_start = time_musec();

        let mut t_last_render: f64 = -65536.0;
        let mut t_last_emit: f64 = -65536.0;

        while !quit {
            let t = 1e-6 * ((time_musec() - t_start) as f64);

            if (t - t_last_render) * (self.framerate as f64) > 1.0 {
                // let _ = stdout().queue(Clear(ClearType::All)); // flickering...

                if render {
                    self.render(paused);
                } else {
                    print_str_def(0, 0, "Render OFF");
                }
                print_str_def((h >> 1) + 2, 0, & format!("This realm: \"{}'s\" (birth: {:?}, survival: {:?}), SLE {:.1}, autoemit ({:.1}) {}, InConnsN {}", & self.name, & self.birth, & self.survival, t - t_last_emit, self.autoemit_interval, if autoemit {"ON"} else {"OFF"}, self.efunguz.in_connections_num()));
                clear_row_right();
                let mut others_str = String::new();
				for i in 0..self.others.len() {
                    if i > 0 {
                        others_str += ", ";
                    }
                    let other = & self.others[i];
                    others_str += & format!("[{}] \"{}'s\"", i + 1, & other.name);
                    if let Some(eh) = self.efunguz.get_ehypha(& other.publickey) {
                        if let Some(et) = eh.get_etale("zone") {
                            others_str += & format!(" (SLU {:.1})", t - 1e-6 * ((et.t_in() - t_start) as f64));
                        }
                    }
                }
				print_str_def((h >> 1) + 3, 0, & format!("Other realms: {}", &others_str));
                clear_row_right();
                
                print_str_def(n_rows - 3, 0, "[Q] quit, [C] clear, [R] reset, [V] render on/off, [P] pause/resume");
                clear_row_right();
				print_str_def(n_rows - 2, 0, "[A] autoemit on/off, [E] emit, [1-9] import");
                clear_row_right();
				print_str_def(n_rows - 1, 0, "If paused: [T] turn, [→ ↑ ← ↓] move cursor, [ ] flip cell");
                clear_row_right();

                let _ = stdout().flush();

                t_last_render = t;
            }

            if autoemit && (t - t_last_emit > self.autoemit_interval) {
                self.emit_etales();
                t_last_emit = t;
            }

            self.update_efunguz();

            if !paused {
                self.turn();
            }

            while let Ok(true) = event::poll(Duration::from_secs(0)) {
                if let Ok(Event::Key(ke)) = event::read() {
                    if let KeyCode::Char(c) = ke.code {
                        match c {
                            'q' | 'Q' => {
                                quit = true;
                            },
                            'c' | 'C' => {
                                self.clear();
                            },
                            'r' | 'R' => {
                                self.reset();
                            },
                            'v' | 'V' => {
                                let _ = queue!(stdout(), Clear(ClearType::All));
                                render = !render;
                            },
                            'p' | 'P' => {
                                paused = !paused;
                            },
                            'a' | 'A' => {
                                autoemit = !autoemit;
                            },
                            'e' | 'E' => {
                                self.emit_etales();
                                t_last_emit = t;
                            },
                            '1'..='9' => {
                                let i_other = (c as usize) - ('1' as usize);
                                if i_other < self.others.len() {
                                    let mut parts: Vec<Vec<u8>> = Vec::new();
                                    if let Some(eh) = self.efunguz.get_ehypha(& self.others[i_other].publickey) {
                                        if let Some(et) = eh.get_etale("zone") {
                                            parts = et.parts().clone();
                                        }
                                    }
                                    self.put_parts_to_zone(&parts);
                                }
                            },
                            _ => {}
                        }
                    }

                    if paused {
                        match ke.code {
                            KeyCode::Char(c) => {
                                match c {
                                    't' | 'T' => {
                                        self.turn();
                                    },
                                    ' ' => {
                                        self.flip(None, None);
                                    },
                                    _ => {}
                                }
                            },
                            KeyCode::Right => {
                                self.move_cursor(0, 1);
                            },
                            KeyCode::Up => {
                                self.move_cursor(-1, 0);
                            },
                            KeyCode::Left => {
                                self.move_cursor(0, -1);
                            },
                            KeyCode::Down => {
                                self.move_cursor(1, 0);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

}

fn run_realm(name: &str) -> Result<(), String> {
    let (
        secretkey, pubport,
        that1_name, that1_publickey, that1_onion, that1_port,
        that2_name, that2_publickey, that2_onion, that2_port,
        birth, survival
    ) = match name.to_ascii_uppercase().as_str() {
        "ALIEN" => {
            (
                ALIEN_SECRETKEY, ALIEN_PORT,
                "John", JOHN_PUBLICKEY, JOHN_ONION, JOHN_PORT,
                "Mary", MARY_PUBLICKEY, MARY_ONION, MARY_PORT,
                HashSet::<usize>::from([3, 4]), HashSet::<usize>::from([3, 4]) // 3-4 Life
            )
        },
        "JOHN" => {
            (
                JOHN_SECRETKEY, JOHN_PORT,
                "Alien", ALIEN_PUBLICKEY, ALIEN_ONION, ALIEN_PORT,
                "Mary", MARY_PUBLICKEY, MARY_ONION, MARY_PORT,
                HashSet::<usize>::from([3]), HashSet::<usize>::from([2, 3]) // classic Conway's Life
            )
        },
        "MARY" => {
            (
                MARY_SECRETKEY, MARY_PORT,
                "Alien", ALIEN_PUBLICKEY, ALIEN_ONION, ALIEN_PORT,
                "John", JOHN_PUBLICKEY, JOHN_ONION, JOHN_PORT,
                HashSet::<usize>::from([3]), HashSet::<usize>::from([2, 3]) // classic Conway's Life
            )
        },
        _ => {
            return Err(format!("Unknown realm name: \"{}\". Must be \"Alien\", \"John\", or \"Mary\".", name))
        }
    };

    let (height, width) = match terminal::size() {
        Ok((w, h)) => {(
            ((h as i16) - 8) << 1, // even
            (w as i16) - 2
        )},
        _ => {
            return Err(String::from("Cannot obtain terminal size"));
        }
    };

    let mut realm = Realm_CA::new(name, secretkey, & HashSet::new(), pubport, height, width, &birth, &survival, DEF_AUTOEMIT_INTERVAL, DEF_FRAMERATE);

    // Uncomment to restrict: Alien gets data from John and Mary; John gets data from Alien but not from Mary; Mary gets data from neither Alien, nor John
    // realm.efunguz.add_whitelist_publickeys(& HashSet::from([String::from(that1_publickey)]));

    realm.add_other(that1_name, that1_publickey, that1_onion, that1_port);
	realm.add_other(that2_name, that2_publickey, that2_onion, that2_port);

    realm.reset();

    init_term_graphics()?;

    realm.run();

    drop_term_graphics()?;

    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    if args.len() >= 2 {
        match run_realm(& args[1]) {
            Ok(_) => {},
            Err(s) => {
                println!("Error: {}", s);
            }
        }
    } else {
        println!("Syntax:");
        println!("demo <Alien|John|Mary>");
    }
}